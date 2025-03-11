#!/bin/sh

# This is a lazy script to create a .deb for Debian/Ubuntu. It installs
# ruvchain and enables it in systemd. You can give it the PKGARCH= argument
# i.e. PKGARCH=i386 sh contrib/deb/generate.sh

if [ `pwd` != `git rev-parse --show-toplevel` ]
then
  echo "You should run this script from the top-level directory of the git repo"
  exit 1
fi

PKGBRANCH=$(basename `git name-rev --name-only HEAD`)
PKGNAME=$(sh contrib/semver/name.sh)
PKGVERSION=$(sh contrib/semver/version.sh --bare)
PKGARCH=${PKGARCH-amd64}
PKGFILE=$PKGNAME-$PKGVERSION-$PKGARCH.deb
PKGREPLACES=ruvchain

if [ $PKGBRANCH = "master" ]; then
  PKGREPLACES=ruvchain-develop
fi

GOLDFLAGS="-X github.com/ruvcoindev/ruvchain-go/src/config.defaultConfig=/etc/ruvchain/ruvchain.conf"
GOLDFLAGS="${GOLDFLAGS} -X github.com/ruvcoindev/ruvchain-go/src/config.defaultAdminListen=unix:///var/run/ruvchain/ruvchain.sock"

if [ $PKGARCH = "amd64" ]; then GOARCH=amd64 GOOS=linux ./build -l "${GOLDFLAGS}"
elif [ $PKGARCH = "i386" ]; then GOARCH=386 GOOS=linux ./build -l "${GOLDFLAGS}"
elif [ $PKGARCH = "mipsel" ]; then GOARCH=mipsle GOOS=linux ./build -l "${GOLDFLAGS}"
elif [ $PKGARCH = "mips" ]; then GOARCH=mips64 GOOS=linux ./build -l "${GOLDFLAGS}"
elif [ $PKGARCH = "armhf" ]; then GOARCH=arm GOOS=linux GOARM=6 ./build -l "${GOLDFLAGS}"
elif [ $PKGARCH = "arm64" ]; then GOARCH=arm64 GOOS=linux ./build -l "${GOLDFLAGS}"
elif [ $PKGARCH = "armel" ]; then GOARCH=arm GOOS=linux GOARM=5 ./build -l "${GOLDFLAGS}"
else
  echo "Specify PKGARCH=amd64,i386,mips,mipsel,armhf,arm64,armel"
  exit 1
fi

echo "Building $PKGFILE"

mkdir -p /tmp/$PKGNAME/
mkdir -p /tmp/$PKGNAME/debian/
mkdir -p /tmp/$PKGNAME/usr/bin/
mkdir -p /tmp/$PKGNAME/lib/systemd/system/

cat > /tmp/$PKGNAME/debian/changelog << EOF
Please see https://github.com/ruvcoindev/ruvchain-go/
EOF
echo 9 > /tmp/$PKGNAME/debian/compat
cat > /tmp/$PKGNAME/debian/control << EOF
Package: $PKGNAME
Version: $PKGVERSION
Section: golang
Priority: optional
Architecture: $PKGARCH
Replaces: $PKGREPLACES
Conflicts: $PKGREPLACES
Depends: systemd
Maintainer: ruvcoindev <ruvcoindev@users.noreply.github.com>
Description: Ruvchain Network
 Ruvchain is an early-stage implementation of a fully end-to-end encrypted IPv6
 network. It is lightweight, self-arranging, supported on multiple platforms and
 allows pretty much any IPv6-capable application to communicate securely with
 other Ruvchain nodes.
EOF
cat > /tmp/$PKGNAME/debian/copyright << EOF
Please see https://github.com/ruvcoindev/ruvchain-go/
EOF
cat > /tmp/$PKGNAME/debian/docs << EOF
Please see https://github.com/ruvcoindev/ruvchain-go/
EOF
cat > /tmp/$PKGNAME/debian/install << EOF
usr/bin/ruvchain usr/bin
usr/bin/ruvchainctl usr/bin
lib/systemd/system/*.service lib/systemd/system
EOF
cat > /tmp/$PKGNAME/debian/postinst << EOF
#!/bin/sh

systemctl daemon-reload

if ! getent group ruvchain 2>&1 > /dev/null; then
  groupadd --system --force ruvchain
fi

if [ ! -d /etc/ruvchain ];
then
    mkdir -p /etc/ruvchain
    chown root:ruvchain /etc/ruvchain
    chmod 750 /etc/ruvchain
fi

if [ ! -f /etc/ruvchain/ruvchain.conf ];
then
    test -f /etc/ruvchain.conf && mv /etc/ruvchain.conf /etc/ruvchain/ruvchain.conf
fi

if [ -f /etc/ruvchain/ruvchain.conf ];
then
  mkdir -p /var/backups
  echo "Backing up configuration file to /var/backups/ruvchain.conf.`date +%Y%m%d`"
  cp /etc/ruvchain/ruvchain.conf /var/backups/ruvchain.conf.`date +%Y%m%d`

  echo "Normalising and updating /etc/ruvchain/ruvchain.conf"
  /usr/bin/ruvchain -useconf -normaliseconf < /var/backups/ruvchain.conf.`date +%Y%m%d` > /etc/ruvchain/ruvchain.conf

  chown root:ruvchain /etc/ruvchain/ruvchain.conf
  chmod 640 /etc/ruvchain/ruvchain.conf
else
  echo "Generating initial configuration file /etc/ruvchain/ruvchain.conf"
  /usr/bin/ruvchain -genconf > /etc/ruvchain/ruvchain.conf

  chown root:ruvchain /etc/ruvchain/ruvchain.conf
  chmod 640 /etc/ruvchain/ruvchain.conf
fi

systemctl enable ruvchain
systemctl restart ruvchain

exit 0
EOF
cat > /tmp/$PKGNAME/debian/prerm << EOF
#!/bin/sh
if command -v systemctl >/dev/null; then
  if systemctl is-active --quiet ruvchain; then
    systemctl stop ruvchain || true
  fi
  systemctl disable ruvchain || true
fi
EOF

cp ruvchain /tmp/$PKGNAME/usr/bin/
cp ruvchainctl /tmp/$PKGNAME/usr/bin/
cp contrib/systemd/ruvchain-default-config.service.debian /tmp/$PKGNAME/lib/systemd/system/ruvchain-default-config.service
cp contrib/systemd/ruvchain.service.debian /tmp/$PKGNAME/lib/systemd/system/ruvchain.service

tar --no-xattrs -czvf /tmp/$PKGNAME/data.tar.gz -C /tmp/$PKGNAME/ \
  usr/bin/ruvchain usr/bin/ruvchainctl \
  lib/systemd/system/ruvchain.service \
  lib/systemd/system/ruvchain-default-config.service
tar --no-xattrs -czvf /tmp/$PKGNAME/control.tar.gz -C /tmp/$PKGNAME/debian .
echo 2.0 > /tmp/$PKGNAME/debian-binary

ar -r $PKGFILE \
  /tmp/$PKGNAME/debian-binary \
  /tmp/$PKGNAME/control.tar.gz \
  /tmp/$PKGNAME/data.tar.gz

rm -rf /tmp/$PKGNAME
