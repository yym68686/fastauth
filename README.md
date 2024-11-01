# FastAuth

Docker build

```bash
docker build --no-cache -t fastauth:latest -f Dockerfile --platform linux/amd64 .
docker tag fastauth:latest yym68686/fastauth:latest
docker push yym68686/fastauth:latest
```