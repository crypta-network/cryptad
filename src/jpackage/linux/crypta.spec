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

ensure_user() {
  if ! id -u cryptad >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
      useradd --system --home-dir /var/lib/cryptad --shell /usr/sbin/nologin \
        --comment "Cryptad service user" cryptad || true
    fi
  fi
}

is_desktop() {
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -q '^display-manager\.service$'; then
      if systemctl is-enabled display-manager >/dev/null 2>&1 || systemctl is-active display-manager >/dev/null 2>&1; then
        return 0
      fi
    fi
  fi
  ls /usr/share/xsessions/*.desktop >/dev/null 2>&1 && return 0
  ls /usr/share/wayland-sessions/*.desktop >/dev/null 2>&1 && return 0
  return 1
}

APP_DIR="/opt/cryptad/crypta"
SERVICE_SRC="$APP_DIR/lib/systemd/system/cryptad.service"
SERVICE_DST="/etc/systemd/system/cryptad.service"

if is_desktop; then
  DESKTOP_COMMANDS_INSTALL
else
  if [ -f "$SERVICE_SRC" ]; then
    ensure_user
    install -D -m 0644 "$SERVICE_SRC" "$SERVICE_DST"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
      systemctl enable cryptad.service || true
      systemctl start cryptad.service || true
    fi
  fi
fi

%pre
package_type=rpm
if [ "$1" = 2 ]; then
  true;
fi

%preun
package_type=rpm

is_desktop() {
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -q '^display-manager\.service$'; then
      if systemctl is-enabled display-manager >/dev/null 2>&1 || systemctl is-active display-manager >/dev/null 2>&1; then
        return 0
      fi
    fi
  fi
  ls /usr/share/xsessions/*.desktop >/dev/null 2>&1 && return 0
  ls /usr/share/wayland-sessions/*.desktop >/dev/null 2>&1 && return 0
  return 1
}

if is_desktop; then
  DESKTOP_COMMANDS_UNINSTALL
else
  if command -v systemctl >/dev/null 2>&1; then
    # Avoid TOCTOU between unit existence check and disable/stop by probing state.
    if systemctl is-enabled cryptad.service >/dev/null 2>&1 \
       || systemctl is-active cryptad.service >/dev/null 2>&1; then
      systemctl disable --now cryptad.service >/dev/null 2>&1 || true
    fi
    rm -f /etc/systemd/system/cryptad.service || true
    systemctl daemon-reload || true
  fi
fi

%clean
