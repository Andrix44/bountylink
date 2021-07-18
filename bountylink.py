#!/usr/bin/env python3
import argparse
import coloredlogs
import logging
import os
import re
from shutil import copyfile
import subprocess
import yaml

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

def RunTool(cmd, name, timeout_s=None):
    logging.info(f"Running {name}")
    logging.debug(f"Command: {cmd}")
    try:
        subprocess.run(cmd, check=True, timeout=timeout_s)
    except subprocess.CalledProcessError:
        logging.critical(f"Something went wrong while running {name}. Exiting...")
        exit(-1)
    logging.info(f"{name} has finished running")

def Amass():
    path = paths["amass_path"]

    options = project["amass"]
    o_enabled = options["enabled"]
    o_active = options["active"]
    o_alts = options["alterations"]
    o_share = options["share"]
    o_silent = options["silent"]
    o_verbose = options["verbose"]
    o_timeout = options["timeout"]
    o_config = options["config"]

    general = project["general"]
    blacklists = general["blacklists"]
    domains = general["rootdomains"].replace(" ",  ",")
    try:
        blacklisted = blacklists["blacklisted_subdoms"].replace(" ",  ",")
    except:
        blacklisted = False

    if(not o_enabled):
        logging.info("amass disabled. Skipping...")
        return

    cmd = []
    cmd.append(path)
    cmd.append("enum")
    if(o_active):
        cmd.append("-active")
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
    if(blacklisted):
        cmd.append("-bl"); cmd.append(blacklisted)
    cmd.append("-dir"); cmd.append(directory + "amass")
    if(o_config != "UNDEFINED"):
        cmd.append("-config"); cmd.append(o_config)

    RunTool(cmd, "amass")

    try:
        blisted_url_components = blacklists["blacklisted_url_components"].replace(" ", "|")
    except:
        blisted_url_components = False

    if(blisted_url_components):
        with open(directory + "amass/amass.txt") as f:
            urls = [line.strip() for line in f]

        unsafe_matching = "" if blacklists["unsafe_matching"] else "[\.-]"
        regex_str = f".*({blisted_url_components}){unsafe_matching}.*"
        logging.debug(f"Blacklist regex: {regex_str}")
        compiled = re.compile(regex_str)

        blacklisted_urls = []
        valid_urls = []
        for url in urls:
            if(compiled.match(url)):
                blacklisted_urls.append(url + '\n')
            else:
                valid_urls.append(url + '\n')

        with open(directory + "amass/cleaned.txt", 'w') as f:
            f.writelines(valid_urls)
        with open(directory + "amass/blocked.txt", 'w') as f:
            f.writelines(blacklisted_urls)
    else:
        copyfile(directory + "amass/amass.txt", directory + "amass/cleaned.txt")

def Subdomains():
    Amass()
    # TODO: masscan()

def Eyewitness():
    path = paths["eyewitness_path"]

    options = project["eyewitness"]
    o_enabled = options["enabled"]
    o_prependhttps = options["prependhttps"]
    o_noprompt = options["noprompt"]
    o_skipdns = options["skipdns"]
    o_timeout = options["timeout"]
    o_jitter = options["jitter"]
    o_delay = options["delay"]
    o_maxretry = options["maxretry"]

    if(not o_enabled):
        logging.info("eyewitness disabled. Skipping...")
        return

    cmd = []
    cmd.append(path)
    cmd.append("-f"); cmd.append(directory + "amass/cleaned.txt")
    cmd.append("-d"); cmd.append(directory + "eyewitness")
    if(o_prependhttps):
        cmd.append("--prepend-https")
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
    path = paths["takeover_path"]

    options = project["takeover"]
    o_enabled = options["enabled"]
    o_threads = options["threads"]
    o_timeout = options["timeout"]

    if(not o_enabled):
        logging.info("takeover disabled. Skipping...")
        return

    newdir = directory + "takeover/"
    os.makedirs(newdir, exist_ok=True)

    cmd = []
    cmd.append(path)
    cmd.append("-l"); cmd.append(directory + "amass/cleaned.txt")
    cmd.append("-o"); cmd.append(newdir + "takeover.txt")
    cmd.append("-t"); cmd.append(str(o_threads))
    cmd.append("-T"); cmd.append(str(o_timeout))

    RunTool(cmd, "takeover")

def AvailableForPurchase():
    path = paths["availableforpurchase_path"]

    o_enabled = project["availableforpurchase"]["enabled"]

    if(not o_enabled):
        logging.info("availableForPurchase disabled. Skipping...")
        return

    cmd = []
    cmd.append("echo"); cmd.append(project["general"]["rootdomains"].replace(" ",  "\n"))
    hosts = subprocess.run(cmd, check=True, capture_output=True)
    
    cmd = []
    cmd.append("python3"); cmd.append(path)
    available = subprocess.run(cmd, input=hosts.stdout, capture_output=True)

    output = available.stdout.decode()
    logging.info(output)
    newdir = directory + "availableForPurchase/"
    os.makedirs(newdir, exist_ok=True)
    with open(newdir + "output.txt", 'w') as f:
        f.write(output)

def Takeovers():
    Takeover()
    AvailableForPurchase()

def FindAllLinks():
    path = paths["find-all-links_path"]

    o_enabled = project["find-all-links"]["enabled"]

    if(not o_enabled):
        logging.info("find-all-links disabled. Skipping...")
        return

    with open(directory + "amass/amass.txt", 'r') as f: # out of scope subdomains shouldn't be an issue here, this just pulls stuff from the web archive
        subdomains = [line.strip() for line in f]

    newdir = directory + "find-all-links/"
    os.makedirs(newdir, exist_ok=True)

    for subdom in subdomains:
        filepath = newdir + f"{subdom}.txt"
        cmd = []
        cmd.append(path)
        cmd.append(subdom)
        cmd.append(filepath)
        try:
            RunTool(cmd, f"find-all-links({subdom})", 180)
            if(os.path.getsize(filepath) == 0):
                os.remove(filepath)
        except subprocess.TimeoutExpired:
            logging.error(f"find-all-links({subdom}) has timed out and was killed.")

if(__name__ == "__main__"):
    print("Bountylink by Andrix")
    Setup()
    Subdomains()
    Eyewitness()
    Takeovers()
    FindAllLinks()
