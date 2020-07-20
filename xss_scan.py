import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import sys

print("-" * 60)
print("CROSS SITE SCRIPTING SCAN TARGET: " + sys.argv[1])
print("-" * 60)
#To retrieve and parse all area's where an XSS injection can be utilised
def get_forms(url):
    """Returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")

    return soup.find_all("form")

#Extract and return details such as the action, method and input attributes
def get_form_details(form):
    """This function extracts all possible useful information about a form"""
    details = {}
    #retrieve form action from target url
    action = form.attrs.get("action").lower()
    #retrieve the form methods
    method = form.attrs.get("method", "get").lower()
    #retrieve input details
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    #compile the results in a dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    # print("--------------------------------------------------")
    # print("[+] The following form details are available")
    # print("--------------------------------------------------")
    # print("     Actions Available = ", action)
    # print("     Methods Available = ", method)
    # print("     Inputs Available  = ", input)

    return details

    #Funtion to submit any returned form
def submit_form(form_details, url, value):
    """Submits form supplied by form_details
        Parameters:
            form_details(list): the above dictionary that contains the form info
            url(str): the original URL that contains the form
            value(str): the payload
        Returns the HTTP response after the form is submitted"""

    #construction of the URL
    target_url = urljoin(url, form_details["action"])
    #retrieve inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        #replace all text and search values with the payload
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")

        if input_name and input_value:
            #providing the name and value are not 'NONE', then add to the form data submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

#vulnerability scan
def scan_xss(url):
    """Supplied with a URL, it will print all forms and return true if vulnerable or false if not"""
    #Retrieve all forms from the URL target
    forms = get_forms(url)
    print(f"[+]) Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('I am vulnerable')</scripT>"
    #Return value
    is_vulnerable = False
    #Repeat for all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()

        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form_details:")
            pprint(form_details)
            is_vulnerable = True

            #Not issuing Break command as we want to print all Forms.
    if is_vulnerable == False:
        print("-------------------------------------------------------")
        print("The detected forms do not contain any known XSS Vulnerability")
        print("-------------------------------------------------------")
    else:
        print("-------------------------------------------------------")
        print("The detected form(s) contain known XSS Vulnerabilities")
        print("-------------------------------------------------------")
    return is_vulnerable

if __name__ == "__main__":
    url = sys.argv[1]
    scan_xss(url)


    # print(scan_xss(url))
