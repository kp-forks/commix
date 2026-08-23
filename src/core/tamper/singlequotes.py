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

import re
from src.utils import settings
from src.core.injections.controller import checks

"""
About: Adds single quotes (') between the characters in a given payload.
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "singlequotes"
__priority__ = settings.PRIORITY.BELOW_NORMAL

def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  obf_char = "''"
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def add_single_quotes(payload):
    payload = re.sub(settings.TAMPER_MODIFICATION_LETTERS, lambda x: obf_char + x[0], payload)
    return checks.tamper_restore_ignored_words(payload, obf_char)
  if settings.TARGET_OS != settings.OS.WINDOWS:
    return add_single_quotes(payload)
  else:
    return payload

# eof