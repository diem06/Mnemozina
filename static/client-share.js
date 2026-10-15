function renderShareQr(text) {
    const box = document.getElementById("share-qr");
    const error = document.getElementById("share-error");
    const area = document.getElementById("share-link");
    area.value = text || "";
    box.innerHTML = "";
    error.classList.add("hidden");
    error.textContent = "";
    if (!text) {
        error.textContent = "Пустая ссылка";
        error.classList.remove("hidden");
        return;
    }
    try {
        qrcode.stringToBytes = qrcode.stringToBytesFuncs["UTF-8"];
        const code = qrcode(0, "M");
        code.addData(text);
        code.make();
        box.innerHTML = code.createImgTag(6, 12, "QR-код для подключения");
    } catch (err) {
        error.textContent = "Ссылка слишком длинная для QR. Скопируйте её текстом.";
        error.classList.remove("hidden");
    }
}

function openShareModal(title, text) {
    document.getElementById("share-title").textContent = title || "Подключение";
    renderShareQr(text);
    document.getElementById("share-modal").classList.remove("hidden");
}

function showShareError(title, message) {
    document.getElementById("share-title").textContent = title || "Подключение";
    document.getElementById("share-qr").innerHTML = "";
    document.getElementById("share-link").value = "";
    const error = document.getElementById("share-error");
    error.textContent = message;
    error.classList.remove("hidden");
    document.getElementById("share-modal").classList.remove("hidden");
}

function closeShare() {
    document.getElementById("share-modal").classList.add("hidden");
}

async function copyText(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        const area = document.createElement("textarea");
        area.value = text;
        document.body.appendChild(area);
        area.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(area);
        return ok;
    }
}

async function copyShareLink() {
    const text = document.getElementById("share-link").value;
    if (!text) return;
    await copyText(text);
}

async function fetchClientLink(button) {
    const body = new URLSearchParams();
    body.set("client_id", button.dataset.clientId || "");
    body.set("client_name", button.dataset.clientName || "");
    const response = await fetch(CLIENT_SHARE_URL, { method: "POST", body });
    const data = await response.json();
    if (!data.ok) {
        throw new Error(data.error || "Не удалось получить ссылку");
    }
    return data.link || data.config || "";
}

async function showClientQr(button) {
    const name = button.dataset.clientName || "Клиент";
    document.getElementById("share-title").textContent = name;
    document.getElementById("share-qr").innerHTML = "";
    document.getElementById("share-error").classList.add("hidden");
    document.getElementById("share-link").value = "Загрузка…";
    document.getElementById("share-modal").classList.remove("hidden");
    try {
        const link = await fetchClientLink(button);
        renderShareQr(link);
    } catch (err) {
        showShareError(name, err.message);
    }
}

async function copyClientLink(button) {
    const previous = button.textContent;
    try {
        const link = await fetchClientLink(button);
        const ok = await copyText(link);
        button.textContent = ok ? "Скопировано" : "Ошибка";
    } catch (err) {
        showShareError(button.dataset.clientName || "Клиент", err.message);
        button.textContent = "Ошибка";
    }
    setTimeout(() => {
        button.textContent = previous;
    }, 1600);
}

document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeShare();
});
