#!/usr/bin/env python3
import argparse
import coloredlogs
import logging
import os
import re
import requests
from shutil import copyfile
import subprocess
import yaml

def Unique(items):
    seen = set()
    for i in range(len(items)-1, -1, -1):
        it = items[i]
        if it in seen:
            del items[i]
        else:
            seen.add(it)

def Setup():
    global project
    global config
    global directory
    global paths

    parser = argparse.ArgumentParser()
    parser.add_argument("projectfile", help="The project configuration file (.yml)")
    parser.add_argument("-l", "--loaderdebug", help="Turns on debug logging before the configs are loaded. Will be overwritten afterwards", action="store_true")
    args = parser.parse_args()

    coloredlogs.install(fmt="%(levelname)s:%(message)s")
    if(args.loaderdebug):
        coloredlogs.set_level(10)

    project_path = args.projectfile
    logging.debug(f"Loading project config at {project_path}")
    with open(project_path, 'r') as f:
        project = yaml.safe_load(f)
        logging.debug("Project config loaded:")
        logging.debug(project)

    logging.debug(f"Loading general config at ./config.yml")
    with open("config.yml", 'r') as f:
        config = yaml.safe_load(f)
        logging.debug("General config loaded:")
        logging.debug(config)

    directory = project["general"]["directory"]
    paths = config["paths"]

    verbosity = config["log_level"].upper()
    logging.debug(f"Setting log level to {verbosity}.")
    if(verbosity == "DEBUG"):
        coloredlogs.set_level(10)
    elif(verbosity == "INFO"):
        coloredlogs.set_level(20)
    elif(verbosity == "WARNING"):
        coloredlogs.set_level(30)
    elif(verbosity == "ERROR"):
        coloredlogs.set_level(40)
    elif(verbosity == "CRITICAL"):
        coloredlogs.set_level(50)
    else:
        logging.ERROR("Incorrect log level setting detected. Defaulting to level INFO")
        coloredlogs.set_level(20)

    logging.info(f"Running project {project['general']['name']}")

def RunTool(cmd, name, timeout_s=None, capture=False):
    logging.info(f"Running {name}")
    logging.debug(f"Command: {cmd}")
    try:
        result = subprocess.run(cmd, check=True, timeout=timeout_s, capture_output=capture)
    except subprocess.CalledProcessError:
        logging.critical(f"Something went wrong while running {name}. Exiting...")
        exit(-1)
    logging.info(f"{name} has finished running")
    return result

def Amass():
    o_config = config["paths"]["amass_config"]

    options = project["amass"]
    o_active = options["active"]
    o_alts = options["alterations"]
    o_share = options["share"]
    o_silent = options["silent"]
    o_verbose = options["verbose"]
    o_timeout = options["timeout"]

    general = project["general"]
    domains = ','.join(general["rootdomains"])

    if(not options["enabled"]):
        logging.info("amass disabled. Skipping...")
        return

    cmd = []
    cmd.append(paths["amass"])
    cmd.append("enum")
    if(o_active):
        cmd.append("-active")
    else:
        cmd.append("-passive")
    if(not o_alts):
        cmd.append("-noalts")
    if(o_share):
        cmd.append("-share")
    if(o_silent):
        cmd.append("-silent")
    if(o_verbose):
        cmd.append("-v")
    if(o_timeout > 0):
        cmd.append("-timeout"); cmd.append(str(o_timeout))
    cmd.append("-d") ;cmd.append(domains)
    cmd.append("-dir"); cmd.append(directory + "amass")
    if(o_config):
        cmd.append("-config"); cmd.append(o_config)

    RunTool(cmd, "amass")

def Shuffledns():
    options = project["shuffledns"]
    o_retries = options["retries"]
    o_verbose = options["verbose"]
    o_silent = options["silent"]
    o_threads = options["threads"]
    o_wc_checks = options["wildcard_checks"]

    domains = project["general"]["rootdomains"]

    if(not options["enabled"]):
        logging.info("shuffledns disabled. Skipping...")
        return

    newdir = directory + "shuffledns/"
    os.makedirs(newdir, exist_ok=True)

    for domain in domains:
        tempfile_path = f"/tmp/dnslist_{domain}"
        with open(paths["subdomain_wordlist"], 'r') as f:
            subdomlist = [(line.strip() + f".{domain}\n") for line in f]
        with open(tempfile_path, 'w') as f:
            f.writelines(subdomlist)

        cmd = []
        cmd.append(paths["shuffledns"])
        cmd.append("-d"); cmd.append(domain)
        cmd.append("-list"); cmd.append(tempfile_path)
        cmd.append("-r"); cmd.append(paths["dns_resolvers"])
        cmd.append("-o"); cmd.append(newdir + f"{domain}.txt")
        cmd.append("-massdns"); cmd.append(paths["massdns"])
        cmd.append("-retries"); cmd.append(str(o_retries))
        if(o_verbose):
            cmd.append("-v")
        if(o_silent):
            cmd.append("-silent")
        cmd.append("-t"); cmd.append(str(o_threads))
        cmd.append("-wt"); cmd.append(str(o_wc_checks))

        RunTool(cmd, f"shuffledns({domain})")

        os.remove(tempfile_path)

def SDomainCleanup():
    logging.info("Cleaning up subdomains...")
    blacklists = project["general"]["blacklists"]
    urls = []

    if(project["amass"]["enabled"]):
        with open(directory + "amass/amass.txt", 'r') as f:
            urls += [line for line in f]

    if(project["shuffledns"]["enabled"]):
        files = os.listdir(directory + "shuffledns/")
        for file in files:
            with open(directory + "shuffledns/" + file, 'r') as f:
                urls += [line for line in f]

    Unique(urls)
    newdir = directory + "bl_subdomains/"
    os.makedirs(newdir, exist_ok=True)

    blisted_url_components = blacklists["blacklisted_url_components"] or []
    blisted_subdomains = blacklists["blacklisted_subdoms"] or []
    if(blisted_url_components or blisted_subdomains): # separating these would have been harder
        re_part = '|'.join(blisted_url_components)
        unsafe_matching = "[\.-]" if blacklists["unsafe_matching"] else ""
        regex_str = f".*({re_part}){unsafe_matching}.*"
        logging.debug(f"Blacklist regex: {regex_str}")
        compiled = re.compile(regex_str)

        blacklisted_urls = []
        valid_urls = []
        for url in urls:
            if(compiled.match(url) or (url.strip() in blisted_subdomains)):
                blacklisted_urls.append(url)
            else:
                valid_urls.append(url)

        with open(newdir + "cleaned.txt", 'w') as f:
            f.writelines(valid_urls)
        with open(newdir + "blocked.txt", 'w') as f:
            f.writelines(blacklisted_urls)
    else:
        with open(newdir + "cleaned.txt", 'w') as f:
            f.writelines(urls)

    logging.info("Subdomain cleanup has finished running")

def Subdomains():
    Amass()
    Shuffledns()
    if(project["amass"]["enabled"] or project["shuffledns"]["enabled"]):
        SDomainCleanup()

def Httprobe():
    path = paths["httprobe"]

    options = project["httprobe"]
    o_threads = options["threads"]
    o_timeout = options["timeout"]

    if(not options["enabled"]):
        logging.info("httprobe disabled. Skipping...")
        return

    logging.info(f"Running httprobe")

    cmd = []
    cmd.append("cat"); cmd.append(directory + "bl_subdomains/cleaned.txt")
    logging.debug(f"Command part 1: {cmd}")
    hosts = subprocess.run(cmd, check=True, capture_output=True)
    
    cmd = []
    cmd.append(path);
    cmd.append("--prefer-https")
    cmd.append("-c"); cmd.append(str(o_threads))
    cmd.append("-t"); cmd.append(str(o_timeout))
    logging.debug(f"Command part 2: {cmd}")
    found = subprocess.run(cmd, input=hosts.stdout, capture_output=True)

    newdir = directory + "httprobe/"
    os.makedirs(newdir, exist_ok=True)

    with open(newdir + "webservers.txt", 'w') as f:
        f.write(found.stdout.decode())

    logging.info(f"httprobe has finished running")

def Eyewitness():
    user_agent = config["user_agent"]

    options = project["eyewitness"]
    o_prependhttps = options["prependhttps"]
    o_noprompt = options["noprompt"]
    o_skipdns = options["skipdns"]
    o_timeout = options["timeout"]
    o_jitter = options["jitter"]
    o_delay = options["delay"]
    o_maxretry = options["maxretry"]

    if(not options["enabled"]):
        logging.info("eyewitness disabled. Skipping...")
        return

    cmd = []
    cmd.append(paths["eyewitness"])
    cmd.append("-f"); cmd.append(directory + "httprobe/webservers.txt")
    cmd.append("-d"); cmd.append(directory + "eyewitness")
    if(user_agent):
        cmd.append("--user-agent"); cmd.append(user_agent)
    if(o_noprompt):
        cmd.append("--no-prompt")
    if(o_skipdns):
        cmd.append("--no-dns")
    if(o_timeout > 0):
        cmd.append("--timeout"); cmd.append(str(o_timeout))
    if(o_jitter > 0):
        cmd.append("--jitter"); cmd.append(str(o_jitter))
    if(o_delay > 0):
        cmd.append("--delay"); cmd.append(str(o_delay))
    if(o_maxretry >= 0):
        cmd.append("--max-retries"); cmd.append(str(o_maxretry))

    RunTool(cmd, "eyewitness")

def Takeover():
    options = project["takeover"]
    o_threads = options["threads"]
    o_timeout = options["timeout"]

    if(not options["enabled"]):
        logging.info("takeover disabled. Skipping...")
        return

    newdir = directory + "takeover/"
    os.makedirs(newdir, exist_ok=True)

    cmd = []
    cmd.append(paths["takeover"])
    cmd.append("-l"); cmd.append(directory + "httprobe/webservers.txt")
    cmd.append("-o"); cmd.append(newdir + "takeover.txt")
    cmd.append("-t"); cmd.append(str(o_threads))
    cmd.append("-T"); cmd.append(str(o_timeout))

    RunTool(cmd, "takeover")

def AvailableForPurchase():
    if(not project["availableforpurchase"]["enabled"]):
        logging.info("availableForPurchase disabled. Skipping...")
        return

    logging.info(f"Running availableforpurchase")

    cmd = []
    cmd.append("echo"); cmd.append('\n'.join(project["general"]["rootdomains"]))
    logging.debug(f"Command part 1: {cmd}")
    hosts = subprocess.run(cmd, check=True, capture_output=True)
    
    cmd = []
    cmd.append("python3"); cmd.append(paths["availableforpurchase"])
    logging.debug(f"Command part 2: {cmd}")
    available = subprocess.run(cmd, input=hosts.stdout, capture_output=True)

    output = available.stdout.decode()
    logging.info(output)
    newdir = directory + "availableForPurchase/"
    os.makedirs(newdir, exist_ok=True)
    with open(newdir + "output.txt", 'w') as f:
        f.write(output)

    logging.info(f"availableforpurchase has finished running")

def Takeovers():
    Takeover()
    AvailableForPurchase()

def Webanalyze():
    path = config["paths"]["webanalyze"]

    options = project["webanalyze"]
    o_redirect = options["redirect"]
    o_crawl = options["crawl"]
    o_worker = options["worker"]
    o_silent = options["silent"]
    o_update = options["update"]

    if(not options["enabled"]):
        logging.info("webanalyze disabled. Skipping...")
        return

    newdir = directory + "webanalyze/"
    os.makedirs(newdir, exist_ok=True)

    cmd = []
    cmd.append(path)
    cmd.append("-hosts"); cmd.append(directory + "httprobe/webservers.txt")
    cmd.append("-apps"); cmd.append("/".join(path.split("/")[:-1]) + "/technologies.json") # assumes that the apps file is in the same directory as the elf
    cmd.append("-output"); cmd.append("stdout") # the output can be later turned into json for other tools, but for now readable output is better
    if(o_redirect):
        cmd.append("-redirect")
    if(o_silent):
        cmd.append("-silent")
    if(o_update):
        cmd.append("-update")
    if(o_crawl > 0):
        cmd.append("-crawl"); cmd.append(str(o_crawl))
    cmd.append("-worker"); cmd.append(str(o_worker))

    result = RunTool(cmd, "webanalyze", capture=True)
    with open(newdir + "webanalyze.txt", 'w') as f:
        f.write(result.stdout.decode())

def Corsy():
    path = paths["corsy"]
    user_agent = config["user_agent"]

    options = project["corsy"]
    o_quiet = options["quiet"]
    o_threads = options["threads"]
    o_delay = options["delay"]

    if(not options["enabled"]):
        logging.info("corsy disabled. Skipping...")
        return

    newdir = directory + "corsy/"
    os.makedirs(newdir, exist_ok=True)

    cmd = []
    cmd.append("python3"); cmd.append(path)
    cmd.append("-i"); cmd.append(directory + "httprobe/webservers.txt")
    cmd.append("-o"); cmd.append(newdir + "corsy.json")
    if(o_quiet):
        cmd.append("-q")
    if(o_threads > 0):
        cmd.append("-t"); cmd.append(str(o_threads))
    if(o_delay > 0):
        cmd.append("-d"); cmd.append(str(o_delay))
    if(user_agent):
        cmd.append("--headers"); cmd.append("User-Agent: " + user_agent)

    RunTool(cmd, "corsy")

def Gau():
    o_threads = project["gau"]["threads"]

    if(not project["gau"]["enabled"]):
        logging.info("gau disabled. Skipping...")
        return

    with open(directory + "bl_subdomains/cleaned.txt", 'r') as f: # also pull stuff from subdomains that aren't running webservers anymore
        subdomains = [line.strip() for line in f]

    if(os.path.isfile(directory + "bl_subdomains/blocked.txt")):
        with open(directory + "bl_subdomains/blocked.txt", 'r') as f: # out of scope subdomains shouldn't be an issue here, this just pulls stuff from the web
            subdomains += [line.strip() for line in f]

    newdir = directory + "gau/"
    os.makedirs(newdir, exist_ok=True)

    for subdom in subdomains:
        filepath = newdir + f"{subdom}.txt"
        cmd = []
        cmd.append(paths["gau"])
        cmd.append("-o"); cmd.append(filepath)
        cmd.append("-t"); cmd.append(str(o_threads))
        cmd.append(subdom)
        try:
            RunTool(cmd, f"gau({subdom})", 300)
            if(os.path.getsize(filepath) == 0):
                os.remove(filepath)
        except subprocess.TimeoutExpired:
            logging.error(f"gau({subdom}) has timed out and was killed.")

def Gitleaks():
    options = project["gitleaks"]
    o_skip_forks = options["skip_forks"]
    o_verbose = options["verbose"]
    o_quiet = options["quiet"]

    repos = project["general"]["git_repos"]
    orgs = project["general"]["git_orgs"]

    if(not project["gitleaks"]["enabled"] or (not repos and not orgs)):
        logging.info("gitleaks disabled or no inputs provided. Skipping...")
        return

    newdir = directory + "gitleaks/"
    os.makedirs(newdir, exist_ok=True)

    for org in orgs:
        r = requests.get(f"https://api.github.com/orgs/{org}/repos")
        data = yaml.safe_load(r.text)
        for obj in data:
            if(not obj["fork"] or not o_skip_forks):
                repos.append(obj["html_url"])

    for repo in repos:
        cmd = []
        cmd.append(paths["gitleaks"])
        cmd.append("-r"); cmd.append(repo)
        cmd.append("-o"); cmd.append(newdir +  f"{'_'.join(repo.split('/')[-2:])}.json")
        cmd.append("--leaks-exit-code"); cmd.append("0")
        if(o_verbose):
            cmd.append("-v")
        if(o_quiet):
            cmd.append("-q")
        RunTool(cmd, f"gitleaks({repo})")

    leaks = os.listdir(newdir)
    for leak in leaks:
        if(os.path.getsize(newdir + leak) == 5): # remove the files If no leaks were found
            os.remove(newdir + leak)
    logging.info("Cleaned up the results that had no leaks")

if(__name__ == "__main__"):
    print("Bountylink by Andrix")
    Setup()
    Subdomains()
    Httprobe()
    Eyewitness()
    Takeovers()
    Webanalyze()
    Corsy()
    Gau()
    Gitleaks()
