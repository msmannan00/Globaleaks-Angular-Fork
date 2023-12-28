import os
import json

def generate_project_structure(root_path):
    project_structure = {}

    for item in os.listdir(root_path):
        item_path = os.path.join(root_path, item)
        item_data = None

        if os.path.isdir(item_path):
            item_data = generate_project_structure(item_path)
        else:
            # Extract the file extension
            _, file_extension = os.path.splitext(item)
            item_data = file_extension

        project_structure[item] = item_data

    return project_structure

project_root_path = "client"
project_structure_json = generate_project_structure(project_root_path)

with open("project_structure.json", "w") as json_file:
    json.dump(project_structure_json, json_file, indent=4)

print("Project structure JSON has been saved to project_structure.json")
