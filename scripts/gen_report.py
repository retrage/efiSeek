#!/usr/bin/env python3

import sys
from typing import Final

from parse import parse
from junitparser import Error, JUnitXml, TestCase, TestSuite

def parse_logline(line):
  LOG_FORMAT: Final = "{date:ti} {time:tt} {log_level:5} ({module:w}) {message}  \n"
  result = parse(LOG_FORMAT, line)
  if result is None:
    return None
  return (result["date"], result["time"], result["log_level"], result["module"], result["message"])

def create_testcase_from_log(loginfo):
  SMM_CALLOUT_LOG_FORMAT: Final = "Potential SMM callout detected at {func_name:w}({func_addr:x}) : {addr:x}"
  SMM_GET_VARIABLE_OVERFLOW_LOG_FORMAT: Final = "Potential GetVariable overflow detected at {func_name:w}({func_addr:x}) : {addr1:x} and {addr2:x}"
  _, _, log_level, module, message = loginfo
  if module != "EfiSeek":
    return None
  if log_level == "WARN ":
    print(message.encode("utf-8"))
    result = parse(SMM_GET_VARIABLE_OVERFLOW_LOG_FORMAT, message)
    if result is not None:
      testcase = TestCase(name="Potential SMM GetVariable Overflow : {addr1:#x} and {addr2:#x}".format(addr1=result["addr1"], addr2=result["addr2"]), classname="{func_addr:#x}".format(func_addr=result["func_addr"]))
      testcase.result = [Error()]
      testcase.system_err = message
      return testcase
    result = parse(SMM_CALLOUT_LOG_FORMAT, message)
    if result is not None:
      testcase = TestCase(name="Potential SMM Callout : {addr:#x}".format(addr=result["addr"]), classname="{func_addr:#x}".format(func_addr=result["func_addr"]))
      testcase.result = [Error()]
      testcase.system_err = message
      return testcase
  return None

def main():
  if len(sys.argv) < 3:
    print("Usage: gen_report.py <input_file> <output_file>")
    return -1
  
  input_file = sys.argv[1]
  output_file = sys.argv[2]

  # TODO: Use binary name for test suite name
  testsuite = TestSuite(name=input_file)

  with open(input_file, 'r') as f:
    for line in f:
      loginfo = parse_logline(line)
      if loginfo is None:
        continue
      testcase = create_testcase_from_log(loginfo)
      if testcase is not None:
        testsuite.add_testcase(testcase)
  xml= JUnitXml("Ghidra efiSeek Static SMM Analysis")
  xml.add_testsuite(testsuite)
  xml.write(output_file)

  return 0

if __name__ == "__main__":
  sys.exit(main())