FROM docker.uib.gmbh/opsi/dev/pybuilder:deb9-py3.11

ARG DEV_USER

ENV LC_ALL="en_US.UTF-8" \
	LANG="en_US.UTF-8" \
	LANGUAGE="en_US:en" \
	DEV_USER=${DEV_USER} \
	OPSI_REPO=https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.3:/development/Debian_9.0/
	# python:
	#PYTHONFAULTHANDLER=1 \
	#PYTHONUNBUFFERED=1 \
	#PYTHONHASHSEED=random \
	# pip:
	#PIP_NO_CACHE_DIR=off \
	#PIP_DISABLE_PIP_VERSION_CHECK=on \
	#PIP_DEFAULT_TIMEOUT=100

RUN apt-get update \
	&& apt-get --yes dist-upgrade\
	&& apt-get --yes --allow-downgrades install \
		sudo \
		zsh \
		git \
		openssh-client \
		inetutils-ping \cpio \
		vim \
		nano \
		wget \
		gettext \
		mariadb-client \
		libmariadb-dev \
		psmisc \
		librsync1 \
		libsqlite3-0=3.16.2-5+deb9u1 \
		netcat \
		apt-transport-https \
	&& mkdir -p /usr/local/share/keyrings \
	&& wget -q -O - ${OPSI_REPO}Release.key | gpg --dearmor > /usr/local/share/keyrings/opsi-obs.gpg \
	&& echo "deb [signed-by=/usr/local/share/keyrings/opsi.gpg] ${OPSI_REPO} /" > /etc/apt/sources.list.d/opsi.list \
	&& apt-get --yes install opsi-utils \
	&& sed -i 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
	&& locale-gen \
	&& sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" \
	&& git clone https://github.com/zsh-users/zsh-autosuggestions /root/.oh-my-zsh/custom/plugins/zsh-autosuggestions \
	&& git clone https://github.com/zsh-users/zsh-syntax-highlighting.git /root/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting \
	&& git clone --depth=1 https://github.com/romkatv/powerlevel10k.git /root/.oh-my-zsh/custom/themes/powerlevel10k \
	&& usermod -s /bin/zsh root

COPY files/ /

RUN if [ -n "$DEV_USER" ]; then \
	useradd --create-home -s /bin/zsh ${DEV_USER} \
	&& echo "${DEV_USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
	&& cp -a /root/.zshrc /root/.oh-my-zsh /root/.p10k.zsh  /root/.zsh_history /home/${DEV_USER}/ \
	&& chown -R ${DEV_USER}:${DEV_USER} /home/${DEV_USER} \
	&& chmod -R g-rww,o-rww /home/${DEV_USER}/.oh-my-zsh \
	; fi \
	&& (getent group opsifileadmins || groupadd opsifileadmins) \
	&& (getent group opsiadmin || groupadd opsiadmin) \
	&& (getent passwd opsiconfd || useradd --system -g opsifileadmins -d /var/lib/opsiconfd/home -s /bin/zsh opsiconfd) \
	&& (getent passwd pcpatch || useradd -d /var/lib/opsi -s /bin/sh pcpatch) \
	&& adduser pcpatch opsifileadmins \
	&& (getent passwd adminuser || useradd --create-home -d /home/adminuser -s /bin/zsh adminuser) \
	&& echo "adminuser:adminuser" | chpasswd \
	&& adduser adminuser opsifileadmins \
	&& adduser adminuser opsiadmin \
	&& echo "${DEV_USER}:adminuser" | chpasswd \
	&& adduser ${DEV_USER} opsifileadmins \
	&& adduser ${DEV_USER} opsiadmin \
	&& adduser ${DEV_USER} sudo \
	&& adduser ${DEV_USER} shadow \
	#&& chown -R ${DEV_USER}:${DEV_USER} /home/${DEV_USER}/ \
	&& echo "${DEV_USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
	#&& cp -r /root/.bash* /home/adminuser/ \
	#&& cp -r /root/.bash* /home/${DEV_USER}/ \
	#&& chmod g+rw -R . \
	&& chmod +x /entrypoint.sh \
	&& mkdir tftpboot \
	&& chown -R $DEV_USER /workspace

ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "sleep", "infinity" ]