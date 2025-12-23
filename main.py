"""
Entry point for Linear-PBFT project
"""

import argparse
import logging

from runtime.manager import RuntimeManager
from utils.logger import LOG_FORMAT, DATE_FORMAT


def parse_args():
    parser = argparse.ArgumentParser(description="Linear-PBFT runtime")
    parser.add_argument("--config", default="config.json", help="Path to config file")
    parser.add_argument("--tests", default="CSE535-F25-Project-2-Testcases.csv", help="Path to CSV test cases")
    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(level=logging.ERROR, format=LOG_FORMAT, datefmt=DATE_FORMAT)
    logging.getLogger("transport").setLevel(logging.ERROR)
    logging.getLogger("ClientDriver").setLevel(logging.ERROR)
    logging.getLogger("RuntimeManager").setLevel(logging.ERROR)
    logging.getLogger("TestOrchestrator").setLevel(logging.ERROR)
    logging.getLogger("asyncio").setLevel(logging.ERROR)
    manager = RuntimeManager(config_path=args.config, test_csv=args.tests)
    manager.initialize()
    manager.run()


if __name__ == "__main__":
    main()
