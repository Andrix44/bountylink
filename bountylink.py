#!/usr/bin/env python3
import argparse
import coloredlogs
import logging
import os
import subprocess
import yaml

def setup():
    global project
    global config

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

def RunTool(cmd, name):
    logging.info(f"Running {name}")
    logging.debug(f"Command: {cmd}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        logging.critical(f"Something went wrong while running {name}. Exiting...")
        exit(-1)
    logging.info(f"{name} has finished running")

def amass():
    path = config["paths"]["amass_path"]

    options = project["amass"]
    o_enabled = options["enabled"]
    o_active = options["active"]
    o_alts = options["alterations"]
    o_share = options["share"]
    o_silent = options["silent"]
    o_verbose = options["verbose"]
    o_timeout = options["timeout"]

    general = project["general"]
    directory = general["directory"]
    domains = general["rootdomains"].replace(" ",  ",")
    blacklisted = general["blacklisted"].replace(" ",  ",")

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
    cmd.append("-dir"); cmd.append(directory + "/amass")

    RunTool(cmd, "amass")

def subdomains():
    amass()
    # TODO: masscan()

def eyewitness():
    path = config["paths"]["eyewitness_path"]
    directory = project["general"]["directory"]

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
    cmd.append("-f"); cmd.append(directory + "/amass/amass.txt")
    cmd.append("-d"); cmd.append(directory + "/eyewitness")
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

def takeover():
    path = config["paths"]["takeover_path"]
    directory = project["general"]["directory"]

    options = project["takeover"]
    o_enabled = options["enabled"]
    o_threads = options["threads"]
    o_timeout = options["timeout"]

    if(not o_enabled):
        logging.info("takeover disabled. Skipping...")
        return

    newdir = project["general"]["directory"] + "/takeover/"
    os.mkdir(newdir)

    cmd = []
    cmd.append(path)
    cmd.append("-l"); cmd.append(directory + "/amass/amass.txt")
    cmd.append("-o"); cmd.append(newdir + "takeover.txt")
    cmd.append("-t"); cmd.append(str(o_threads))
    cmd.append("-T"); cmd.append(str(o_timeout))

    RunTool(cmd, "takeover")

if(__name__ == "__main__"):
    print("Bountylink by Andrix")
    setup()
    subdomains()
    eyewitness()
    takeover()