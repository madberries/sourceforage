from bs4 import BeautifulSoup

from .string import make_title


def get_all_forms(url, session, log):
    """Returns all form tags found on a web page's `url` """
    # Issue the GET request.
    res = session.get(url)

    # Make sure the response was OK.
    if res.status_code != 200:
        log.error(f"ERROR: {url} returned status code = " + page.status_code)
        return None

    # Parse and pretty-print the HTML response.
    soup = BeautifulSoup(res.html.html, "html.parser")
    log.debug(make_title('start of HTTP response'))
    log.debug(soup.prettify())
    log.debug(make_title('end of HTTP response'))

    # Return the forms generated from this response.
    return soup.find_all("form")


def get_form_details(form):
    """Returns the HTML details of a form,
    including action, method and list of form controls (inputs, etc)"""
    details = {}

    # Get the form action (requested URL).
    action = form.attrs.get("action").lower()

    # Get the form method (POST, GET, DELETE, etc).  If not specified, GET is
    # the default.
    method = form.attrs.get("method", "get").lower()

    # Get all of the inputs to this form.
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type, "name": input_name, "value": input_value
        })

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details
