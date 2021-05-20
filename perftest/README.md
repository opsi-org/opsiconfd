# opsiconfd performance tests

## opsicxonfd WebDav vs. Apache WebDav

`perf-test-webdav.py` is a small script to compare the webdav server used in opsiconfd and apache webdav.
To use the script you have to mount the opsiconfd and the apache webdav folder and specify the mount point with `--opsiconfd-mount` / `--apache-mount`.
With `--folder` you set the folder that will be copied.

`perf-test-webdav.py --help`

```
usage: perf-test-webdav.py [-h] [--opsiconfd-mount OPSICONFD_MOUNT]
                           [--apache-mount APACHE_MOUNT] [--folder FOLDER]
                           [--destination DESTINATION]

optional arguments:
  -h, --help            show this help message and exit
  --opsiconfd-mount OPSICONFD_MOUNT
                        Path to WebDav mount
  --apache-mount APACHE_MOUNT
                        Path to WebDav mount
  --folder FOLDER       folder to copy
  --destination DESTINATION
                        destination
```

Hier are some test results:

- folder with 846mb
	- opsiconfd:  20.34s
	- apache:  8.84s
- folder with 66mb
	- opsiconfd:  2.07s
	- apache:  0.83s
