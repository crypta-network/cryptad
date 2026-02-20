Summary: APPLICATION_SUMMARY
Name: APPLICATION_PACKAGE
Version: APPLICATION_VERSION
Release: APPLICATION_RELEASE
License: APPLICATION_LICENSE_TYPE
Vendor: APPLICATION_VENDOR

%if "xAPPLICATION_URL" != "x"
URL: APPLICATION_URL
%endif

%if "xAPPLICATION_PREFIX" != "x"
Prefix: APPLICATION_PREFIX
%endif

Provides: APPLICATION_PACKAGE

%if "xAPPLICATION_GROUP" != "x"
Group: APPLICATION_GROUP
%endif

Autoprov: 0
Autoreq: 0
%if "xPACKAGE_DEFAULT_DEPENDENCIES" != "x" || "xPACKAGE_CUSTOM_DEPENDENCIES" != "x"
Requires: PACKAGE_DEFAULT_DEPENDENCIES PACKAGE_CUSTOM_DEPENDENCIES
%endif

%define __jar_repack %{nil}
%define _build_id_links none

%define package_filelist %{_builddir}/%{name}.files
%define app_filelist %{_builddir}/%{name}.app.files
%define filesystem_filelist %{_builddir}/%{name}.filesystem.files

%define default_filesystem / /opt /usr /usr/bin /usr/lib /usr/local /usr/local/bin /usr/local/lib

%description
APPLICATION_DESCRIPTION

%global __os_install_post %{nil}

%prep

%build

%install
rm -rf %{buildroot}
install -d -m 755 %{buildroot}APPLICATION_DIRECTORY
cp -r %{_sourcedir}APPLICATION_DIRECTORY/* %{buildroot}APPLICATION_DIRECTORY
%if "xAPPLICATION_LICENSE_FILE" != "x"
  %define license_install_file %{_defaultlicensedir}/%{name}-%{version}/%{basename:APPLICATION_LICENSE_FILE}
  install -d -m 755 "%{buildroot}%{dirname:%{license_install_file}}"
  install -m 644 "APPLICATION_LICENSE_FILE" "%{buildroot}%{license_install_file}"
%endif
(cd %{buildroot} && find . -type d -print) | sed -e 's/^\.//' -e '/^$/d' | sort > %{app_filelist}
{ rpm -ql filesystem || echo %{default_filesystem}; } | sort > %{filesystem_filelist}
comm -23 %{app_filelist} %{filesystem_filelist} > %{package_filelist}
sed -i -e 's/.*/%dir "&"/' %{package_filelist}
(cd %{buildroot} && find . -not -type d) | sed -e 's/^\.//' -e 's/.*/"&"/' >> %{package_filelist}
%if "xAPPLICATION_LICENSE_FILE" != "x"
  sed -i -e 's|"%{license_install_file}"||' -e '/^$/d' %{package_filelist}
%endif

%files -f %{package_filelist}
%if "xAPPLICATION_LICENSE_FILE" != "x"
  %license "%{license_install_file}"
%endif

%post
package_type=rpm

# Source common helpers from installed image when available
APP_DIR="/opt/cryptad/crypta"
[ -d "/opt/cryptad/Crypta" ] && APP_DIR="/opt/cryptad/Crypta"
COMMON="$APP_DIR/lib/crypta-common.sh"
[ -f "$COMMON" ] && . "$COMMON"
command -v log_line >/dev/null 2>&1 || log_line() { echo "$*"; }
log_line "post: APP_DIR='$APP_DIR'"

# Fallbacks if helpers are not available
command -v is_desktop >/dev/null 2>&1 || is_desktop() {
  if command -v systemctl >/dev/null 2>&1; then
    # Consider enabled/active display-manager or common DM units (gdm, sddm, lightdm, ly, xdm)
    if systemctl is-enabled display-manager >/dev/null 2>&1 || \
       systemctl is-active display-manager >/dev/null 2>&1; then
      return 0
    fi
    for dm in gdm sddm lightdm ly xdm; do
      if systemctl is-enabled "$dm" >/dev/null 2>&1 || \
         systemctl is-active "$dm" >/dev/null 2>&1; then
        return 0
      fi
    done
  fi
  ls /usr/share/xsessions/*.desktop >/dev/null 2>&1 && return 0
  ls /usr/share/wayland-sessions/*.desktop >/dev/null 2>&1 && return 0
  return 1
}

if is_desktop; then
  log_line "post: detected desktop environment"
else
  log_line "post: server environment (no desktop)"
fi

command -v ensure_user >/dev/null 2>&1 || ensure_user() {
  if ! getent group cryptad >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then
      groupadd --system cryptad || true
    fi
  fi
  if ! id -u cryptad >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
      useradd --system --home-dir /var/lib/cryptad --shell /usr/sbin/nologin \
        --gid cryptad --comment "Cryptad service user" cryptad || true
    fi
  fi
  install -d -m 0750 -o cryptad -g cryptad /var/lib/cryptad || true
}

SERVICE_SRC="$APP_DIR/lib/systemd/system/cryptad.service"
SERVICE_DST="/etc/systemd/system/cryptad.service"
HELPER_UNIT_SRC="$APP_DIR/lib/systemd/system/cryptad-core-install@.service"
HELPER_UNIT_DST="/etc/systemd/system/cryptad-core-install@.service"
HELPER_SCRIPT_SRC="$APP_DIR/lib/cryptad-core-install.sh"
POLKIT_SRC="$APP_DIR/lib/polkit-1/60-cryptad-core-install.rules"
POLKIT_DST="/usr/share/polkit-1/rules.d/60-cryptad-core-install.rules"

if is_desktop; then
  # Install desktop entry into system-wide applications dir and refresh caches
  DESKTOP_SRC="$APP_DIR/lib/crypta-Crypta.desktop"
  DESKTOP_DST="/usr/share/applications/crypta.desktop"
  log_line "post: DESKTOP_SRC='$DESKTOP_SRC' exists=$([ -f "$DESKTOP_SRC" ] && echo yes || echo no)"
  if [ -f "$DESKTOP_SRC" ]; then
    install -D -m 0644 "$DESKTOP_SRC" "$DESKTOP_DST"
    log_line "post: installed desktop -> $DESKTOP_DST"
    # Normalize Exec/Icon to the actual app dir; ensure WM_CLASS keys exist.
    sed -i "s|^Exec=.*|Exec=$APP_DIR/bin/Crypta|" "$DESKTOP_DST" || true
    sed -i "s|^Icon=.*|Icon=$APP_DIR/lib/cryptad.png|" "$DESKTOP_DST" || true
    grep -q '^StartupWMClass=' "$DESKTOP_DST" || echo 'StartupWMClass=network-crypta-launcher-Launcher' >> "$DESKTOP_DST"
    grep -q '^X-GNOME-WMClass=' "$DESKTOP_DST" || echo 'X-GNOME-WMClass=network-crypta-launcher-Launcher' >> "$DESKTOP_DST"
    log_line "post: patched $DESKTOP_DST (Exec/Icon/WM_CLASS)"
    # Also patch the image copy for consistency so future packaging picks up the same values.
    sed -i "s|^Exec=.*|Exec=$APP_DIR/bin/Crypta|" "$DESKTOP_SRC" || true
    sed -i "s|^Icon=.*|Icon=$APP_DIR/lib/cryptad.png|" "$DESKTOP_SRC" || true
    grep -q '^StartupWMClass=' "$DESKTOP_SRC" || echo 'StartupWMClass=network-crypta-launcher-Launcher' >> "$DESKTOP_SRC"
    grep -q '^X-GNOME-WMClass=' "$DESKTOP_SRC" || echo 'X-GNOME-WMClass=network-crypta-launcher-Launcher' >> "$DESKTOP_SRC"
    log_line "post: patched image copy $DESKTOP_SRC"
  else
    log_line "post: WARNING: missing $DESKTOP_SRC; cannot install desktop entry"
  fi
  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
    log_line "post: updated desktop database"
  fi
  if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
    log_line "post: refreshed icon cache"
  fi
else
  if [ -f "$SERVICE_SRC" ]; then
    ensure_user
    install -D -m 0644 "$SERVICE_SRC" "$SERVICE_DST"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
      systemctl enable cryptad.service || true
    fi
    log_line "post: installed/enabled systemd service"
  fi
fi

# Always install headless helper unit + polkit rule and ensure script is executable
if [ -f "$HELPER_UNIT_SRC" ]; then
  install -D -m 0644 "$HELPER_UNIT_SRC" "$HELPER_UNIT_DST"
  sed -i "s|/opt/cryptad/crypta|$APP_DIR|g" "$HELPER_UNIT_DST" || true
  log_line "post: installed helper unit -> $HELPER_UNIT_DST"
fi
if [ -f "$HELPER_SCRIPT_SRC" ]; then
  chmod 0755 "$HELPER_SCRIPT_SRC" || true
fi
if [ -f "$POLKIT_SRC" ]; then
  install -D -m 0644 "$POLKIT_SRC" "$POLKIT_DST"
  log_line "post: installed polkit rule -> $POLKIT_DST"
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

%pre
package_type=rpm
if [ "$1" = 2 ]; then
  true;
fi

%postun
package_type=rpm

APP_DIR="/opt/cryptad/crypta"
[ -d "/opt/cryptad/Crypta" ] && APP_DIR="/opt/cryptad/Crypta"
COMMON="$APP_DIR/lib/crypta-common.sh"
[ -f "$COMMON" ] && . "$COMMON"
command -v log_line >/dev/null 2>&1 || log_line() { echo "$*"; }
log_line "postun: APP_DIR='$APP_DIR' arg1='$1'"

# Only on final erase ($1=0) remove desktop/service. On upgrade ($1=1) skip removal.
if [ "$1" = 0 ]; then
  command -v is_desktop >/dev/null 2>&1 || is_desktop() {
    if command -v systemctl >/dev/null 2>&1; then
      if systemctl is-enabled display-manager >/dev/null 2>&1 || \
         systemctl is-active display-manager >/dev/null 2>&1; then
        return 0
      fi
      for dm in gdm sddm lightdm ly xdm; do
        if systemctl is-enabled "$dm" >/dev/null 2>&1 || \
           systemctl is-active "$dm" >/dev/null 2>&1; then
          return 0
        fi
      done
    fi
    ls /usr/share/xsessions/*.desktop >/dev/null 2>&1 && return 0
    ls /usr/share/wayland-sessions/*.desktop >/dev/null 2>&1 && return 0
    return 1
  }

  if is_desktop; then
    rm -f /usr/share/applications/crypta.desktop || true
    if command -v update-desktop-database >/dev/null 2>&1; then
      update-desktop-database -q /usr/share/applications || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
      gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
    fi
    log_line "postun: removed desktop entry"
  else
    if command -v systemctl >/dev/null 2>&1; then
      if systemctl is-enabled cryptad.service >/dev/null 2>&1 \
         || systemctl is-active cryptad.service >/dev/null 2>&1; then
        systemctl disable --now cryptad.service >/dev/null 2>&1 || true
      fi
      rm -f /etc/systemd/system/cryptad.service || true
      systemctl daemon-reload || true
    fi
    log_line "postun: disabled/removed systemd service"
  fi
else
  log_line "postun: upgrade detected; skipping removal"
fi

%clean
