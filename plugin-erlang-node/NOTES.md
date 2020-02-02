* other C nodes implementations:
  * https://github.com/massemanet/cookbook
  * https://github.com/NZ-Jaybird/gen-cnode
  * https://github.com/massemanet/gtknode
* weechat plugin
  * https://github.com/weechat/weechat/blob/master/src/plugins/relay/relay-server.c
  * https://github.com/weechat/weechat/blob/master/src/plugins/relay/relay-client.c

```
$ iex --sname test@localhost
> Node.connect(:weechat@localhost)
> send {:any, :weechat@localhost}, :self
> receive do x -> x end
```
