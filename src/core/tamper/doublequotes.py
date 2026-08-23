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
About: Adds double quotes (") between the characters in a given payload.
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "doublequotes"
__priority__ = settings.PRIORITY.BELOW_NORMAL

def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  obf_char = '""'
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def add_double_quotes(payload):
    if settings.TARGET_OS != settings.OS.WINDOWS:
      payload = re.sub(settings.TAMPER_MODIFICATION_LETTERS, r'""\1', payload)
    else:
      word = "tokens"
      _ = obf_char.join(word[i:i+1] for i in range(-1, len(word), 1))
      payload = payload.replace(word,_)
    return checks.tamper_restore_ignored_words(payload, obf_char)
  return add_double_quotes(payload)

# eof