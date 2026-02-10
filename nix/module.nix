{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.auditarr;
in
{
  options.services.auditarr = {
    enable = mkEnableOption "media audit service";
    
    configFile = mkOption {
      type = types.path;
      description = "Path to auditarr configuration file";
    };
    
    package = mkOption {
      type = types.package;
      default = pkgs.auditarr;
      description = "auditarr package to use";
    };
    
    schedule = mkOption {
      type = types.nullOr types.str;
      default = "monthly";
      description = ''
        Systemd calendar expression for schedule.
        Examples:
        - "monthly" - First day of each month at midnight
        - "weekly" - Monday at midnight
        - "daily" - Every day at midnight
        - "*-*-01,15 02:00:00" - 1st and 15th at 2am
        - "Sun *-*-* 03:00:00" - Every Sunday at 3am
        See: man 7 systemd.time for full syntax
        Set to null to disable automatic runs (manual only).
      '';
    };
    
    user = mkOption {
      type = types.str;
      default = "auditarr";
      description = "User to run auditarr as";
    };
    
    group = mkOption {
      type = types.str;
      default = "auditarr";
      description = "Group to run auditarr as";
    };
  };
  
  config = mkIf cfg.enable {
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = "/var/lib/auditarr";
      createHome = true;
    };
    
    users.groups.${cfg.group} = {};
    
    systemd.services.auditarr = {
      description = "Media Library Audit";
      serviceConfig = {
        Type = "oneshot";
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${cfg.package}/bin/auditarr scan --config=${cfg.configFile}";
        StateDirectory = "auditarr";
        WorkingDirectory = "/var/lib/auditarr";
      };
    };
    
    systemd.timers.auditarr = mkIf (cfg.schedule != null) {
      description = "Run media audit on schedule";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.schedule;
        Persistent = true;
      };
    };
  };
}
