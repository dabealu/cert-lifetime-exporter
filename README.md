### Certificate lifetime exporter
This exporter can grab list of domains from `yandex pdd` and `nic.ru` DNS providers, check remaining certificate lifetime of each domain and serve this metrics in `prometheus` format.  
It's also possible to add or exclude list of domains which will be checked via config file.  
To get list of configuration flags use `--help`, to show example config file use `--sample` flag.  
  
#### Build and run  
Execute `./build.sh` to build docker image `cert-lifetime-exporter`.  
Save config example `docker run --rm -ti cert-lifetime-exporter --sample > config.json`, adjust it with actual values, and run exporter with mounted config:
```
docker run -d \
    --name cert-lifetime-exporter \
    -p 8080:8080 \
    -v $PWD/config.json:/config.json \
    cert-lifetime-exporter
```
metrics are become available at `localhost:8080/metrics`.
