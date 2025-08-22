import os
import importlib.util

MODULES_DIR = os.path.join(os.path.dirname(__file__), "modules")

def load_modules(app):
   if not os.path.exists(MODULES_DIR):
       return
   for filename in os.listdir(MODULES_DIR):
       if filename.endswith(".py"):
           module_path = os.path.join(MODULES_DIR, filename)
           spec = importlib.util.spec_from_file_location(filename[:-3], module_path)
           module = importlib.util.module_from_spec(spec)
           spec.loader.exec_module(module)
           if hasattr(module, "register_modules"):
               module.register_modules(app)
