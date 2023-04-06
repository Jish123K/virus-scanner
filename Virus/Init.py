import importlib

# import the Virustotal class from the virustotalpy.wrapper module

vt_module = importlib.import_module("virustotalpy.wrapper")

Virustotal = vt_module.Virustotal

vtError = vt_module.vtError

