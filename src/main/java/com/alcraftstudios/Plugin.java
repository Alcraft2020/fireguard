package com.alcraftstudios;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Plugin extends JavaPlugin implements Listener {
    private static final Logger LOGGER = Logger.getLogger("fireguard");
    private final Map<String, List<Long>> ipJoinTimestamps = new HashMap<>();
    private final Set<String> blockedIps = new HashSet<>();
    private final Set<String> whitelistIps = new HashSet<>();
    private final Set<UUID> blacklistUuids = new HashSet<>();
    private final Set<String> blacklistIps = new HashSet<>();
    private final Set<String> blacklistNames = new HashSet<>();
    private File whitelistFile;
    private File blacklistFile;
    private int joinThreshold = 5;
    private int blockDurationSeconds = 60;
    private final Map<String, Long> ipBlockExpiry = new HashMap<>();
    private boolean antiVpnEnabled = true;
    private final String githubApiUrl = "https://api.github.com/repos/Alcraft2020/fireguard/releases/latest";
    private final String pluginJarName = "fireguard-0.1.jar";

    @Override
    public void onEnable() {
        LOGGER.info("FireGuard successfully enabled.");
        getServer().getPluginManager().registerEvents(this, this);
        saveDefaultConfig();
        joinThreshold = getConfig().getInt("join-threshold", 5);
        blockDurationSeconds = getConfig().getInt("block-duration-seconds", 60);
        antiVpnEnabled = getConfig().getBoolean("antivpn-enabled", true);
        whitelistFile = new File(getDataFolder(), "whitelist.json");
        blacklistFile = new File(getDataFolder(), "blacklist.json");
        loadWhitelist();
        loadBlacklist();
        getCommand("fireguard").setExecutor(new FireGuardCommandExecutor());
        checkForUpdate();
    }

    private class FireGuardCommandExecutor implements org.bukkit.command.CommandExecutor {
        @Override
        public boolean onCommand(org.bukkit.command.CommandSender sender, org.bukkit.command.Command command, String label, String[] args) {
            if (args.length == 2 && args[0].equalsIgnoreCase("whitelist")) {
                String ip = args[1];
                if (sender.hasPermission("fireguard.whitelist") || !(sender instanceof Player)) {
                    whitelistIps.add(ip);
                    saveWhitelist();
                    sender.sendMessage(ChatColor.GREEN + "IP " + ip + " added to FireGuard whitelist.");
                } else {
                    sender.sendMessage(ChatColor.RED + "You do not have permission to use this command.");
                }
                return true;
            } else if (args.length == 2 && args[0].equalsIgnoreCase("blacklist")) {
                if (!sender.hasPermission("fireguard.blacklist") && sender instanceof Player) {
                    sender.sendMessage(ChatColor.RED + "You do not have permission to use this command.");
                    return true;
                }
                Player target = Bukkit.getPlayer(args[1]);
                if (target != null) {
                    UUID uuid = target.getUniqueId();
                    String ip = (target.getAddress() != null && target.getAddress().getAddress() != null) ? target.getAddress().getAddress().getHostAddress() : "";
                    String name = target.getName();
                    blacklistUuids.add(uuid);
                    if (!ip.isEmpty()) blacklistIps.add(ip);
                    blacklistNames.add(name);
                    saveBlacklist();
                    sender.sendMessage(ChatColor.RED + "User " + name + " (" + ip + ") added to FireGuard blacklist.");
                } else {
                    String name = args[1];
                    blacklistNames.add(name);
                    saveBlacklist();
                    sender.sendMessage(ChatColor.RED + "Offline user " + name + " added to FireGuard blacklist (name only). If they join, their IP and UUID will be added automatically.");
                }
                return true;
            } else if (args.length == 2 && args[0].equalsIgnoreCase("antivpn")) {
                if (!sender.hasPermission("fireguard.antivpn")) {
                    sender.sendMessage(ChatColor.RED + "You do not have permission to use this command.");
                    return true;
                }
                if (args[1].equalsIgnoreCase("on")) {
                    antiVpnEnabled = true;
                    getConfig().set("antivpn-enabled", true);
                    saveConfig();
                    sender.sendMessage(ChatColor.GREEN + "AntiVPN enabled.");
                } else if (args[1].equalsIgnoreCase("off")) {
                    antiVpnEnabled = false;
                    getConfig().set("antivpn-enabled", false);
                    saveConfig();
                    sender.sendMessage(ChatColor.YELLOW + "AntiVPN disabled.");
                } else {
                    sender.sendMessage(ChatColor.YELLOW + "Usage: /fireguard antivpn <on|off>");
                }
                return true;
            } else if (args.length == 1 && args[0].equalsIgnoreCase("update")) {
                if (!sender.hasPermission("fireguard.update")) {
                    sender.sendMessage(ChatColor.RED + "You do not have permission to use this command.");
                    return true;
                }
                sender.sendMessage(ChatColor.YELLOW + "Checking for FireGuard updates...");
                Bukkit.getScheduler().runTaskAsynchronously(Plugin.this, () -> {
                    checkForUpdate();
                });
                return true;
            }
            sender.sendMessage(ChatColor.YELLOW + "Usage: /fireguard whitelist <ip> | /fireguard blacklist <player> | /fireguard antivpn <on|off> | /fireguard update");
            return true;
        }
    }

    private void loadWhitelist() {
        if (!whitelistFile.exists()) {
            whitelistFile.getParentFile().mkdirs();
            saveWhitelist();
            return;
        }
        try (FileReader reader = new FileReader(whitelistFile)) {
            org.json.simple.parser.JSONParser parser = new org.json.simple.parser.JSONParser();
            Object obj = parser.parse(reader);
            org.json.simple.JSONArray arr = (org.json.simple.JSONArray) obj;
            whitelistIps.clear();
            for (Object o : arr) {
                if (o != null) whitelistIps.add(o.toString());
            }
        } catch (Exception e) {
            LOGGER.warning("[FireGuard] Could not load whitelist: " + e.getMessage());
        }
    }

    private void saveWhitelist() {
        try (FileWriter writer = new FileWriter(whitelistFile)) {
            org.json.simple.JSONArray arr = new org.json.simple.JSONArray();
            arr.addAll(whitelistIps);
            writer.write(arr.toJSONString());
        } catch (Exception e) {
            LOGGER.warning("[FireGuard] Could not save whitelist: " + e.getMessage());
        }
    }

    private void loadBlacklist() {
        if (!blacklistFile.exists()) {
            blacklistFile.getParentFile().mkdirs();
            saveBlacklist();
            return;
        }
        try (FileReader reader = new FileReader(blacklistFile)) {
            org.json.simple.parser.JSONParser parser = new org.json.simple.parser.JSONParser();
            Object obj = parser.parse(reader);
            org.json.simple.JSONObject json = (org.json.simple.JSONObject) obj;
            blacklistUuids.clear();
            blacklistIps.clear();
            blacklistNames.clear();
            org.json.simple.JSONArray uuids = (org.json.simple.JSONArray) json.get("uuids");
            org.json.simple.JSONArray ips = (org.json.simple.JSONArray) json.get("ips");
            org.json.simple.JSONArray names = (org.json.simple.JSONArray) json.get("names");
            if (uuids != null) for (Object o : uuids) blacklistUuids.add(UUID.fromString(o.toString()));
            if (ips != null) for (Object o : ips) blacklistIps.add(o.toString());
            if (names != null) for (Object o : names) blacklistNames.add(o.toString());
        } catch (Exception e) {
            LOGGER.warning("[FireGuard] Could not load blacklist: " + e.getMessage());
        }
    }

    private void saveBlacklist() {
        try (FileWriter writer = new FileWriter(blacklistFile)) {
            org.json.simple.JSONObject json = new org.json.simple.JSONObject();
            org.json.simple.JSONArray uuids = new org.json.simple.JSONArray();
            org.json.simple.JSONArray ips = new org.json.simple.JSONArray();
            org.json.simple.JSONArray names = new org.json.simple.JSONArray();
            for (UUID u : blacklistUuids) uuids.add(u.toString());
            ips.addAll(blacklistIps);
            names.addAll(blacklistNames);
            json.put("uuids", uuids);
            json.put("ips", ips);
            json.put("names", names);
            writer.write(json.toJSONString());
        } catch (Exception e) {
            LOGGER.warning("[FireGuard] Could not save blacklist: " + e.getMessage());
        }
    }

    @Override
    public void onDisable() {
        LOGGER.info("FireGuard successfully disabled.");
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        final String ip;
        if (event.getPlayer().getAddress() != null && event.getPlayer().getAddress().getAddress() != null) {
            ip = event.getPlayer().getAddress().getAddress().getHostAddress();
        } else {
            ip = null;
        }
        UUID uuid = event.getPlayer().getUniqueId();
        String name = event.getPlayer().getName();
        long now = System.currentTimeMillis();

        if (ip == null) {
            return;
        }
        if (antiVpnEnabled) {
            Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
                if (isVpnOrProxy(ip)) {
                    Bukkit.getScheduler().runTask(this, () -> {
                        event.getPlayer().kickPlayer(ChatColor.RED + "VPNs and Proxies are blocked on this server.");
                    });
                }
            });
        }

        if (whitelistIps.contains(ip)) {
            return;
        }
        if (blacklistUuids.contains(uuid)) {
            blockedIps.add(ip);
            ipBlockExpiry.put(ip, now + blockDurationSeconds * 1000);
            event.getPlayer().kickPlayer(ChatColor.RED + "You are blacklisted by FireGuard.");
            return;
        }
        if (blacklistIps.contains(ip)) {
            blockedIps.add(ip);
            ipBlockExpiry.put(ip, now + blockDurationSeconds * 1000);
            event.getPlayer().kickPlayer(ChatColor.RED + "Your IP is blacklisted by FireGuard.");
            return;
        }
        for (String blIp : blacklistIps) {
            if (isSimilarIp(ip, blIp)) {
                alertAdmins("IP similar to blacklist detected: " + ip + " ~ " + blIp + " (player: " + name + ")");
                break;
            }
        }
        for (String blName : blacklistNames) {
            if (isSimilarName(name, blName)) {
                alertAdmins("Name similar to blacklist detected: " + name + " ~ " + blName + " (IP: " + ip + ")");
                break;
            }
        }

        if (ipBlockExpiry.containsKey(ip) && now > ipBlockExpiry.get(ip)) {
            blockedIps.remove(ip);
            ipBlockExpiry.remove(ip);
        }

        if (blockedIps.contains(ip)) {
            event.getPlayer().kickPlayer(ChatColor.RED + "Connections from your IP have been temporarily blocked due to suspicious activity.");
            return;
        }

        ipJoinTimestamps.putIfAbsent(ip, new ArrayList<Long>());
        List<Long> timestamps = ipJoinTimestamps.get(ip);
        timestamps.add(now);
        timestamps.removeIf(ts -> now - ts > 60000);

        if (timestamps.size() > joinThreshold) {
            blockedIps.add(ip);
            ipBlockExpiry.put(ip, now + blockDurationSeconds * 1000);
            alertAdmins("Massive connections detected from IP: " + ip + " (" + timestamps.size() + " in 1 minute)");
            event.getPlayer().kickPlayer(ChatColor.RED + "Connections from your IP have been temporarily blocked due to suspicious activity.");
        }
    }

    private void alertAdmins(String msg) {
        for (Player p : Bukkit.getOnlinePlayers()) {
            if (p.hasPermission("fireguard.alert")) {
                p.sendMessage(ChatColor.YELLOW + "[FireGuard] " + msg);
            }
        }
        LOGGER.warning("[FireGuard] " + msg);
    }

    private boolean isSimilarIp(String ip1, String ip2) {
        String[] parts1 = ip1.split("\\.");
        String[] parts2 = ip2.split("\\.");
        return parts1.length >= 2 && parts2.length >= 2 && parts1[0].equals(parts2[0]) && parts1[1].equals(parts2[1]);
    }

    private boolean isSimilarName(String name1, String name2) {
        int minLen = Math.min(name1.length(), name2.length());
        for (int i = 0; i <= minLen - 4; i++) {
            String sub = name1.substring(i, i + 4);
            if (name2.contains(sub)) return true;
        }
        return false;
    }

    private boolean isVpnOrProxy(String ip) {
        try {
            URL url = new URL("http://ip-api.com/json/" + ip + "?fields=proxy,hosting");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setConnectTimeout(3000);
            con.setReadTimeout(3000);
            con.setRequestMethod("GET");
            try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                con.disconnect();
                JSONParser parser = new JSONParser();
                JSONObject obj = (JSONObject) parser.parse(content.toString());
                Boolean proxy = (Boolean) obj.get("proxy");
                Boolean hosting = (Boolean) obj.get("hosting");
                return (proxy != null && proxy) || (hosting != null && hosting);
            }
        } catch (IOException | ParseException e) {
            LOGGER.warning("[FireGuard] Error checking VPN/Proxy: " + e.getMessage());
            return false;
        }
    }

    private void checkForUpdate() {
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            try {
                URL url = new URL(githubApiUrl);
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestProperty("Accept", "application/vnd.github.v3+json");
                con.setConnectTimeout(5000);
                con.setReadTimeout(5000);
                con.setRequestMethod("GET");
                int status = con.getResponseCode();
                if (status == 200) {
                    try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                        StringBuilder content = new StringBuilder();
                        String inputLine;
                        while ((inputLine = in.readLine()) != null) {
                            content.append(inputLine);
                        }
                        JSONParser parser = new JSONParser();
                        JSONObject obj = (JSONObject) parser.parse(content.toString());
                        String latestVersion = (String) obj.get("tag_name");
                        String currentVersion = getDescription().getVersion();
                        if (!latestVersion.equalsIgnoreCase(currentVersion)) {
                            JSONArray assets = (JSONArray) obj.get("assets");
                            if (assets != null && !assets.isEmpty()) {
                                JSONObject asset = (JSONObject) assets.get(0);
                                String downloadUrl = (String) asset.get("browser_download_url");
                                downloadAndReplacePlugin(downloadUrl, latestVersion);
                            }
                        }
                    }
                }
                con.disconnect();
            } catch (Exception e) {
                LOGGER.warning("[FireGuard] Error checking updates: " + e.getMessage());
            }
        });
    }

    private void downloadAndReplacePlugin(String downloadUrl, String latestVersion) {
        try {
            File pluginFile = new File(getFile().getParent(), pluginJarName);
            URL url = new URL(downloadUrl);
            try (InputStreamReader in = new InputStreamReader(url.openStream());
                 FileWriter out = new FileWriter(pluginFile)) {
                int c;
                while ((c = in.read()) != -1) {
                    out.write(c);
                }
            }
            LOGGER.info("[FireGuard] Update downloaded: " + latestVersion + ". Restart the server to apply the new version.");
            alertAdmins("New FireGuard version downloaded: " + latestVersion + ". Restart the server to update.");
        } catch (Exception e) {
            LOGGER.warning("[FireGuard] Error downloading update: " + e.getMessage());
        }
    }
}
