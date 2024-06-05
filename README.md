# nats.conf
```
authorization {
    token: "my-token"
}
```


# Execute nats with nats.conf
```shell
docker run -it --rm -p 4222:4222 -v /path/to/local/nats.conf:/etc/nats.conf nats -js -DVV -c /etc/nats.conf
```

OJO: reemplazar /path/to/local/nats.conf por la ruta al archivo nats.conf que acabamos de crear

## Example
```shell
docker run -it --rm -p 4222:4222 -v /home/prezdev/git-projects/test-token-nats/nats.conf:/etc/nats.conf nats -js -DVV -c /etc/nats.conf
```

# Test
## Subscribe with token
```shell
nats sub test.token -s nats://my-token@localhost:4222
```

## Publish with token
```shell
nats pub test.token "Message test" -s nats://my-token@localhost:4222
```
