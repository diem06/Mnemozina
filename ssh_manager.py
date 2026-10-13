"""
Модуль SSH-подключения к VPS-серверу.
Оборачивает paramiko и предоставляет простой API для выполнения команд.
"""
from __future__ import annotations

import paramiko


class SSHError(Exception):
    """Ошибка при работе с SSH-соединением."""
    pass


class SSHSession:
    """
    Обёртка над SSH-подключением к одному VPS-серверу.

    Использование:
        with SSHSession(host="1.2.3.4", username="root", password="...") as s:
            code, out, err = s.run("docker ps")
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str | None = None,
        port: int = 22,
        key_path: str | None = None,
        timeout: int = 10,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.timeout = timeout
        self.client: paramiko.SSHClient | None = None
        # Amnezia-клиент всегда вызывает "sudo docker". Под root sudo может
        # отсутствовать, поэтому для root используем docker напрямую.
        self.docker = "docker" if username == "root" else "sudo docker"

    def connect(self) -> None:
        """Устанавливает SSH-соединение."""
        self.client = paramiko.SSHClient()
        # Для dev удобно; в проде — RejectPolicy + known_hosts.
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            if self.key_path:
                key = paramiko.RSAKey.from_private_key_file(self.key_path)
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    pkey=key,
                    timeout=self.timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
            else:
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
        except paramiko.AuthenticationException as exc:
            raise SSHError("Ошибка аутентификации: неверный логин или пароль") from exc
        except paramiko.SSHException as exc:
            raise SSHError(f"Ошибка SSH: {exc}") from exc
        except Exception as exc:
            raise SSHError(
                f"Не удалось подключиться к {self.host}:{self.port}: {exc}"
            ) from exc

    def run(
        self,
        command: str,
        timeout: int | None = None,
        input_data: str | bytes | None = None,
    ):
        """
        Выполняет команду на сервере.
        input_data (если задан) передаётся в stdin команды — так удобно
        передавать файлы/скрипты в `docker exec -i` без экранирования.
        Возвращает (exit_code, stdout, stderr).
        """
        if self.client is None:
            self.connect()

        t = timeout or self.timeout
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=t)
            if input_data is not None:
                if isinstance(input_data, str):
                    input_data = input_data.encode("utf-8")
                stdin.write(input_data)
                stdin.flush()
            stdin.channel.shutdown_write()
            # Сначала читаем вывод, потом код возврата — иначе при большом
            # выводе (логи, конфиги) канал может заблокироваться.
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            return exit_code, out, err
        except Exception as exc:
            raise SSHError(f"Ошибка выполнения команды: {exc}") from exc

    def close(self) -> None:
        """Закрывает соединение."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

    def is_alive(self) -> bool:
        """Проверяет, живое ли соединение."""
        if self.client is None:
            return False
        try:
            transport = self.client.get_transport()
            return transport is not None and transport.is_active()
        except Exception:
            return False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()