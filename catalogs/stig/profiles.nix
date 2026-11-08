{
  server = {
    V-268084 = {
      status = "notApplicable";
      reason = "Servers have no graphical logon.";
    };
    V-268086 = {
      status = "notApplicable";
      reason = "Servers have no graphical session to lock.";
    };
  };

  workstation = {
    V-268159 = {
      status = "exception";
      reason = "Workstations do not run sshd.";
    };
    V-268146 = {
      status = "exception";
      reason = "Workstations use Wi-Fi.";
    };
    V-268147 = {
      status = "exception";
      reason = "Workstations use Bluetooth peripherals.";
    };
    V-268139 = {
      status = "exception";
      reason = "Workstations hot-plug USB devices.";
    };
    V-268105.settings.action = "SYSLOG";
    V-268106.settings.action = "SYSLOG";
  };
}
