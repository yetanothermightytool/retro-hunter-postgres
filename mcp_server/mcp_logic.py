import os
import importlib.util

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "tools")

def load_tools(app):
   if not os.path.exists(TOOLS_DIR):
       return
   for filename in os.listdir(TOOLS_DIR):
       if filename.endswith(".py"):
           module_path = os.path.join(TOOLS_DIR, filename)
           spec = importlib.util.spec_from_file_location(filename[:-3], module_path)
           module = importlib.util.module_from_spec(spec)
           spec.loader.exec_module(module)
           if hasattr(module, "register_tool"):
               module.register_tool(app)
