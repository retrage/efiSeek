#!/usr/bin/env python3

import sys
from typing import Final

from parse import parse
from junitparser import Attr, Error, JUnitXml, TestCase, TestSuite

TestCase.file = Attr("file")

def parse_logline(line):
  LOG_FORMAT: Final = "{date:ti} {time:tt} {log_level:5} ({module:w}) {message}  \n"
  result = parse(LOG_FORMAT, line)
  if result is None:
    return None
  return (result["date"], result["time"], result["log_level"], result["module"], result["message"])

def create_smm_callout_testcase(binary_path, log_level, module, message):
  SMM_CALLOUT_LOG_FORMAT: Final = "Potential SMM callout detected at {func_name:w}({func_addr:x}) : {addr:x}"
  if module != "EfiSeek" or log_level != "WARN ":
    return None
  result = parse(SMM_CALLOUT_LOG_FORMAT, message)
  if result is not None:
    addr = result["addr"]
    func_name = result["func_name"]
    func_addr = result["func_addr"]
    testcase = TestCase(name="Potential SMM Callout : {:#x}".format(addr), classname="{}:{:#x}".format(func_name, func_addr))
    testcase.result = [Error()]
    testcase.file = binary_path
    testcase.system_err = message
    return testcase
  return None

def create_smm_get_variable_overflow_testcase(binary_path, log_level, module, message):
  SMM_GET_VARIABLE_OVERFLOW_LOG_FORMAT: Final = "Potential GetVariable overflow detected at {func_name:w}({func_addr:x}) : {addr1:x} and {addr2:x}"
  if module != "EfiSeek" or log_level != "WARN ":
    return None
  result = parse(SMM_GET_VARIABLE_OVERFLOW_LOG_FORMAT, message)
  if result is not None:
    addr1 = result["addr1"]
    addr2 = result["addr2"]
    func_name = result["func_name"]
    func_addr = result["func_addr"]
    testcase = TestCase(name="Potential SMM GetVariable Overflow : {:#x} and {:#x}".format(addr1, addr2), classname="{}:{:#x}".format(func_name, func_addr))
    testcase.result = [Error()]
    testcase.file = binary_path
    testcase.system_err = message
    return testcase
  return None

def get_binary_path(log_level, module, message):
  HEADLESS_ANALYZER_INFO_FORMAT: Final = "ANALYZING all memory and code: {binary_path}" 
  if module != "HeadlessAnalyzer" or log_level != "INFO ":
    return None
  print(message)
  result = parse(HEADLESS_ANALYZER_INFO_FORMAT, message)
  if result is not None:
    return result["binary_path"]
  return None

def main():
  if len(sys.argv) < 3:
    print("Usage: gen_report.py <input_file> <output_file>")
    return -1
  
  input_file = sys.argv[1]
  output_file = sys.argv[2]

  smm_callout_testsuite = TestSuite("SMM Callout")
  smm_get_variable_overflow_testsuite = TestSuite("SMM GetVariable Overflow")

  with open(input_file, 'r') as f:
    binary_path = ""
    for line in f:
      loginfo = parse_logline(line)
      if loginfo is None:
        continue
      _, _, log_level, module, message = loginfo
      path = get_binary_path(log_level, module, message)
      if path is not None:
        binary_path = path
        continue
      testcase = create_smm_callout_testcase(binary_path, log_level, module, message)
      if testcase is not None:
        smm_callout_testsuite.add_testcase(testcase)
        continue
      testcase = create_smm_get_variable_overflow_testcase(binary_path, log_level, module, message)
      if testcase is not None:
        smm_get_variable_overflow_testsuite.add_testcase(testcase)
        continue
  xml= JUnitXml("Ghidra efiSeek Static Analysis")
  xml.add_testsuite(smm_callout_testsuite)
  xml.add_testsuite(smm_get_variable_overflow_testsuite)
  xml.write(output_file)

  return 0

if __name__ == "__main__":
  sys.exit(main())