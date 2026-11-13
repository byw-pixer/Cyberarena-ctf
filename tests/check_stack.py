#!/usr/bin/env python3
"""Проверка запущенного стека: доступность, изоляция лаборатории, отказоустойчивость, ресурсы.

Кросс-платформенная замена bash-скрипта (Windows, macOS, Linux). Нужны только Python 3 и Docker.
Запуск из любой папки при поднятом стеке:

    docker compose up -d --build
    python tests/check_stack.py        # в Windows: python tests\\check_stack.py

В конце проверки вход на сайт примерно на минуту отвечает 429: это проверка ограничения частоты.
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "http://localhost:8080"
failed = []


def report(ok, text):
    print("[ OK ] " + text if ok else "[FAIL] " + text)
    if not ok:
        failed.append(text)


def docker(*args):
    try:
        return subprocess.run(["docker", *args], cwd=ROOT, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        print("Docker не найден. Установите Docker и запустите проект: docker compose up -d --build")
        sys.exit(2)


def compose(*args):
    return docker("compose", *args)


def http(path, method="GET", data=None):
    request = urllib.request.Request(BASE + path, data=data, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as err:
        return 0, str(err)


def container_id(service):
    return compose("ps", "-q", service).stdout.strip()


def inspect(container, template):
    return docker("inspect", container, "--format", template).stdout.strip()


def python_probe(code):
    """Выполняет код внутри лаборатории; True, если он завершился успешно."""
    return compose("exec", "-T", "lab-web", "python", "-c", code).returncode == 0


def main():
    if not container_id("app"):
        print("Стек не запущен. Сначала выполните: docker compose up -d --build")
        return 2
    lab = container_id("lab-web")
    app = container_id("app")

    # доступность
    report(http("/")[0] == 200, "платформа открывается на localhost:8080")
    report(http("/lab/")[0] == 200, "лаборатория открывается через /lab/")
    report(compose("port", "nginx", "80").stdout.strip() == "127.0.0.1:8080", "nginx слушает только 127.0.0.1:8080")
    report(inspect(app, "{{json .HostConfig.PortBindings}}") == "{}", "платформа не опубликована наружу напрямую")

    # изоляция лаборатории
    report(not python_probe("import socket; socket.create_connection(('app', 8000), 2)"), "лаборатория не видит платформу")
    report(not python_probe("import socket; socket.create_connection(('1.1.1.1', 53), 2)"), "у лаборатории нет выхода в интернет")
    report("docker.sock" not in inspect(lab, "{{json .Mounts}}"), "docker.sock в лабораторию не смонтирован")
    report(inspect(lab, "{{.HostConfig.Privileged}}") == "false", "лаборатория не privileged")
    report(inspect(lab, "{{.HostConfig.ReadonlyRootfs}}") == "true", "корневая ФС лаборатории read-only")
    report(inspect(lab, "{{.HostConfig.NetworkMode}}") != "host", "лаборатория без host network")
    report(compose("exec", "-T", "lab-web", "id", "-u").stdout.strip() not in ("", "0"), "лаборатория работает не от root")
    report(json.loads(inspect(lab, "{{json .HostConfig.CapDrop}}") or "[]") == ["ALL"], "у лаборатории сброшены все capabilities")
    report(inspect(lab, "{{.HostConfig.Memory}}") == str(256 * 1024 * 1024), "лимит памяти лаборатории 256 МБ")

    # конфигурация и статика
    report(compose("exec", "-T", "nginx", "nginx", "-t").returncode == 0, "конфигурация Nginx корректна (nginx -t)")
    report(http("/static/style.css")[0] == 200, "платформа раздаёт /static/ (стили)")
    report(http("/static/tasks/web02/vault.js")[0] == 200, "WEB-02: файлы задания доступны")
    report(http("/static/tasks/crypto01/cipher.txt")[0] == 200, "CRYPTO-01: шифротекст доступен")

    # задания и флаги
    report("CTF{" not in http("/")[1], "на главной странице платформы флагов нет")
    report("CTF{" not in http("/lab/notes?id=3")[1], "WEB-01: своя заметка флага не содержит")
    report("CTF{" in http("/lab/notes?id=1")[1], "WEB-01 решается через Nginx (notes?id=1)")
    report("CTF{" not in http("/static/tasks/crypto01/cipher.txt")[1], "в шифротексте CRYPTO-01 флага в открытом виде нет")

    # отказоустойчивость: лаборатория остановлена, платформа жива
    compose("stop", "lab-web")
    lab_status, root_status = http("/lab/")[0], http("/")[0]
    compose("start", "lab-web")
    report(lab_status == 503 and root_status == 200,
           "лаборатория остановлена: /lab/ -> 503 с понятной страницей, платформа -> 200 (получено %s и %s)" % (lab_status, root_status))

    # ограничение частоты в Nginx (в конце: вход блокируется примерно на минуту)
    limited = sum(1 for _ in range(45) if http("/login", "POST", b"x=1")[0] == 429)
    report(limited > 0, "Nginx ограничивает частоту POST /login (429: %d из 45)" % limited)
    print("(подождите около минуты, прежде чем входить на сайт)")

    print("\nПотребление ресурсов:")
    stats = docker("stats", "--no-stream", "--format", "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}")
    print(stats.stdout.strip())
    print("\nИтог: %d проверок не пройдено" % len(failed) if failed else "\nИтог: все проверки пройдены")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
