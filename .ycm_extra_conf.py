def FlagsForFile(*args):
  print(args)
  return { "flags" : ["-O0", "-DLTM_DESC"],
      "do_cache" : False }
