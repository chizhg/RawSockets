import sys
from http.http_client import do_get

DEFAULT_FILE_NAME = "index.html"

if __name__ == "__main__":
    url = sys.argv[1]
    response_data = do_get(url)

    # remove the http prefix
    if url.find("http://") != -1:
        url = url[(len("http://")):]

    # if the url do not contain path or it ends with /, use the
    # default file name
    if url.find("/") == -1 or url.endswith("/"):
        file_name = DEFAULT_FILE_NAME
    else:
        file_name = url[url.rfind("/") + 1 :]

    with open(file_name, "w+") as f:
        f.write(response_data)
