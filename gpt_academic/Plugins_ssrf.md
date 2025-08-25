### **Title: Multiple Server-Side Request Forgery (SSRF) Vulnerabilities in gpt-academic Plugins**

### Summary

The `gpt-academic` project contains multiple plugins that are vulnerable to Server-Side Request Forgery (SSRF). Flawed or non-existent validation of user-supplied URLs allows an attacker to force the server to make requests to arbitrary external websites or, more critically, to internal network services. This can lead to internal port scanning, accessing sensitive internal endpoints, and interacting with cloud metadata services.

Two specific instances are detailed below.

---

### Vulnerability 1: SSRF in "Download and Translate arXiv Paper Abstract" Plugin

#### Description

The "Download and Translate arXiv Paper Abstract" (`下载arxiv论文翻译摘要`) plugin is intended to fetch and process academic papers from `arxiv.org`. Although the code attempts to restrict requests to this domain, the validation logic is insufficient and can be easily bypassed.

#### Cause of Vulnerability

1.  **Direct Use of External Input in Requests:**
    *   The `download_arxiv_()` function accepts a user-controlled `url`. This URL is then passed to `requests.get()` in the `get_name()` function without proper sanitization, allowing an attacker to control the destination of the server-side HTTP request.

    *   **Affected Code:**
        ```python
        # In the plugin logic for "Download and Translate arXiv Paper Abstract"
        def download_arxiv_(url_pdf, ...):
            url_abs = url_pdf.replace('.pdf', '').replace('pdf', 'abs')
            title, other_info = get_name(_url_=url_abs) # The tainted URL is passed here

        # In a utility function
        def get_name(_url_, ...):
            proxies = get_conf('proxies')
            res = requests.get(_url_, proxies=proxies) # SSRF occurs here
        ```

2.  **Flawed Host Validation Logic:**
    *   The code only checks if the substring `'arxiv.org'` is present in the input URL (`if 'arxiv.org' not in url_pdf`). This type of string-based check is inadequate to guarantee that the request's actual host is `arxiv.org`.

    *   **Bypass Technique:** According to RFC 3986, which the `requests` library follows, a URL formatted as `http://allowed-domain@real-target.com` will treat `allowed-domain` as user info and send the request to `real-target.com`. An attacker can therefore use a payload like `http://arxiv.org@localhost` or `http://arxiv.org@192.168.1.1` to bypass the check. The server sees the string "arxiv.org" and allows the request, but the request is actually sent to `localhost` or an internal IP.

    *   **Affected Code:**
        ```python
        if 'arxiv.org' not in url_pdf:
            if ('.' in url_pdf) and ('/' not in url_pdf):
                new_url = 'https://arxiv.org/abs/'+url_pdf
                # ...
                return download_arxiv_(new_url)
            else:
                logger.info('Cannot recognize this URL!')
                return None
        ```

3.  **Lack of Further Restrictions:**
    *   The function does not enforce any whitelists for protocols, ports, or paths. Security measures like DNS pinning or IP whitelisting are not implemented, giving an attacker full freedom to probe internal network assets or cloud metadata APIs (e.g., `169.254.169.254`).

#### Steps to Reproduce

1.  Enter a malicious URL in the input box, such as `http://arxiv.org@127.0.0.1:8080` to target a local service.
2.  Click the "Download and Translate arXiv Paper Abstract" plugin button.
<img width="3840" height="1916" alt="image1" src="https://github.com/user-attachments/assets/8d5391a1-d1c4-4b55-a92f-e634da78fa39" />


**Evidence of successful access to an internal service:**

<img width="1040" height="92" alt="image2" src="https://github.com/user-attachments/assets/413c120e-d021-4ef3-84a8-9d44491a9247" />


**Demonstration of making an arbitrary external request (e.g., to Baidu) using an online deployment of the project:**

<img width="3840" height="2074" alt="image3" src="https://github.com/user-attachments/assets/e19402d3-385d-4ae5-9045-56500e49c6be" />

---

### Vulnerability 2: SSRF in "Batch Translate PDF Documents" Plugin

#### Description

The "Batch Translate PDF Documents" (`批量翻译PDF文档`) plugin, and other plugins that use the `get_files_from_everything` utility, are vulnerable to SSRF because they completely lack validation for remote resource URLs.

#### Cause of Vulnerability

1.  **Uncontrolled User Input:**
    *   In the "Batch Translate PDF Documents" feature, the user-provided input `txt` is passed directly to the `get_files_from_everything` function. This input can be a local path or any arbitrary URL.

2.  **Lack of Effective Validation:**
    *   The code only checks if the input `txt` starts with `http` to determine if it's a remote URL. There are no subsequent checks on the domain, IP address, protocol, or port.

3.  **Direct Backend Request Initiation:**
    *   If the input starts with `http` or `https`, the `get_files_from_everything` function immediately initiates a server-side request using `requests.get(txt)`.

    *   **Affected Code:**
        ```python
        # crazy_functions/批量翻译PDF文档_NOUGAT.py
        def 批量翻译PDF文档(txt, ...):
            # ...
            from crazy_functions.crazy_utils import get_files_from_everything
            success, file_manifest, project_folder = get_files_from_everything(txt, type='.pdf')
            # ...

        # crazy_functions/crazy_utils.py
        def get_files_from_everything(txt, type):
            # ...
            if txt.startswith('http'):
                # It's a remote file from the web
                import requests
                # ...
                try:
                    r = requests.get(txt, proxies=proxies) // SSRF occurs here
        ```

#### Note

The vulnerable `get_files_from_everything` function is used by multiple plugins in the project. All of them are likely affected by this SSRF vulnerability.

#### Proof of Concept (PoC)

1.  Enter a URL pointing to an internal service (e.g., `http://127.0.0.1:5000`) in the input field.
2.  Click the "Batch Translate PDF Documents" plugin button to send the request.
<img width="3840" height="1916" alt="image4" src="https://github.com/user-attachments/assets/6fbc08cc-512a-4bf8-93e3-2ce28f44b35d" />

**Evidence of successful access to an internal service:**
<img width="1098" height="170" alt="image5" src="https://github.com/user-attachments/assets/388207b5-a14d-4e93-9c68-418d9a79af54" />

---

### Impact

An attacker can exploit these vulnerabilities to perform Server-Side Request Forgery (SSRF) attacks. This can lead to:
*   Scanning of the server's internal network to discover open ports and services.
*   Accessing and potentially interacting with sensitive internal applications that lack authentication.
*   Requesting data from cloud provider metadata services (e.g., AWS EC2, Google Cloud) to steal credentials or other sensitive information.
*   Bypassing firewalls and other network-level security controls.

### Recommended Remediation

1.  **Use a Strict Whitelist for Host Validation:** For interfaces intended to only access specific services like `arxiv.org`, implement a strict whitelist.
    *   Parse the URL using a reliable library (e.g., `urllib.parse`).
    *   Perform an exact match on the parsed hostname against the whitelist (e.g., `hostname == 'arxiv.org'`). Do not use substring checks like `'in'`.

2.  **Block Requests to Internal IPs:** For all outgoing requests originating from the server, implement a blacklist to prevent access to internal/private IP address ranges. This includes:
    *   Loopback addresses (`127.0.0.1/8`)
    *   Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
    *   Link-local addresses (`169.254.0.0/16`), which often host cloud metadata services.
 
### Credits

Wenhao Wu, ChengGao, Alibaba Cloud Intelligence Security Team

