# Local Web Workbench

The Web workbench is intended for authorized CTF targets running on the local machine, a virtual machine, or a private network. It combines bounded passive-style crawling with the existing local attachment solver.

## Safety Boundary

- Requires an explicit authorization confirmation before each run.
- Accepts only HTTP and HTTPS targets resolving exclusively to localhost, loopback, link-local, or private-network addresses.
- Keeps every redirect and discovered URL on the original origin.
- Sends GET requests only.
- Does not execute page JavaScript or submit forms.
- Limits crawl depth, request count, response size, redirects, per-request time, and total run time.
- Rejects public Internet targets by default.

The target should still be isolated from sensitive services. The crawler reads reachable same-origin content, including common CTF paths such as `robots.txt`, `sitemap.xml`, `flag`, `debug`, `source`, `backup.zip`, and `.git/HEAD`.

## Analysis Flow

1. Validate the target URL and resolve it to allowed local/private addresses.
2. Fetch the entry page and a small bounded set of common CTF paths.
3. Discover same-origin links, scripts, API routes, forms, source maps, robots entries, and sitemap entries.
4. Inspect response bodies and headers for comments, cookies, debug output, sensitive clue words, and flag-shaped values.
5. Save binary and attachment responses inside the application sandbox.
6. Pass downloaded archives, images, captures, documents, and binaries to the existing recursive local solver.
7. Write Markdown and JSON reports with pages, evidence, errors, flags, and manual follow-up steps.

## Local Training

`npm run smoke:web` starts an isolated synthetic HTTP challenge on `127.0.0.1`. The regression verifies:

- route discovery through `robots.txt`
- JavaScript and source-map discovery
- Cookie and form reporting
- direct flag extraction
- download and recursive ZIP solving
- public-target rejection

For broader manual practice, run an intentionally vulnerable target locally and point the workbench at its private URL. Suitable projects include:

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [Damn Vulnerable Web Application](https://github.com/digininja/DVWA)

Do not point the automatic crawler at public hosted labs unless their rules explicitly allow automated traffic. The workbench intentionally leaves authentication, form submission, exploitation, and state-changing requests to the user.

## Design References

The workflow follows the low-risk discovery principles used by:

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/): entry-point, content, metadata, and execution-path mapping
- [OWASP ZAP Passive Scanner](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/): inspect traffic before active testing
- [Katana](https://github.com/projectdiscovery/katana): explicit scope and crawl limits
- [ffuf](https://github.com/ffuf/ffuf): bounded content discovery with user-controlled targets
