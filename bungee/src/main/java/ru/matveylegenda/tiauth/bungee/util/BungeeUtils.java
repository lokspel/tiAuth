package ru.matveylegenda.tiauth.bungee.util;

import lombok.experimental.UtilityClass;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;

import java.net.InetSocketAddress;

@UtilityClass
public class BungeeUtils {

    public void sendMessage(CommandSender sender, String message) {
        if (message.isBlank()) {
            return;
        }
        sender.sendMessage(TextComponent.fromLegacy(message));
    }

    public String getIp(ProxiedPlayer player) {
        return ((InetSocketAddress) player.getSocketAddress()).getAddress().getHostAddress();
    }
}
