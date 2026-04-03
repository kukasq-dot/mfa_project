// --- 1. УПРАВЛЕНИЕ UI И СОСТОЯНИЕМ ---

window.onload = function() { checkAuthStatus(); };

function checkAuthStatus() {
    const token = localStorage.getItem("jwt_token");
    if (token) {
        document.getElementById("auth-view").style.display = "none";
        document.getElementById("dashboard-view").style.display = "block";
        resetAuthForms();
    } else {
        document.getElementById("auth-view").style.display = "block";
        document.getElementById("dashboard-view").style.display = "none";
    }
}

function switchTab(tabName) {
    document.getElementById("message-auth").innerText = "";
    document.getElementById("loginMfaBlock").style.display = "none";
    
    // Меняем активную вкладку
    document.getElementById("tab-login").classList.remove("active");
    document.getElementById("tab-register").classList.remove("active");
    document.getElementById("tab-" + tabName).classList.add("active");

    // Показываем нужную форму
    document.getElementById("login-form").classList.remove("active");
    document.getElementById("register-form").classList.remove("active");
    document.getElementById(tabName + "-form").classList.add("active"); // <-- Ошибка была здесь
}

function togglePassword(inputId, iconElement) {
    const input = document.getElementById(inputId);
    if (input.type === "password") {
        input.type = "text";
        iconElement.innerText = "🙈";
    } else {
        input.type = "password";
        iconElement.innerText = "👁️";
    }
}

function resetAuthForms() {
    document.getElementById("login-username").value = "";
    document.getElementById("login-password").value = "";
    document.getElementById("loginMfaCode").value = "";
    document.getElementById("reg-username").value = "";
    document.getElementById("reg-password").value = "";
    document.getElementById("reg-password-confirm").value = "";
    document.getElementById("password-rules").style.display = "none";
    document.getElementById("loginMfaBlock").style.display = "none";
}

function showMsg(elementId, msg, color) {
    const el = document.getElementById(elementId);
    el.style.color = color;
    el.innerText = msg;
    setTimeout(() => { el.innerText = ""; }, 6000); 
}

// Управление состоянием загрузки кнопки
function setButtonLoading(buttonId, isLoading, defaultText) {
    const btn = document.getElementById(buttonId);
    if (isLoading) {
        btn.disabled = true;
        btn.innerText = "Ожидание...";
    } else {
        btn.disabled = false;
        btn.innerText = defaultText;
    }
}

// --- 2. ДИНАМИЧЕСКАЯ ВАЛИДАЦИЯ ПАРОЛЯ ---

function updateRuleUI(ruleId, isValid) {
    const el = document.getElementById(ruleId);
    if (isValid) {
        el.className = "valid";
        el.innerHTML = '<span class="rule-icon">✅</span>' + el.innerText.substring(2);
    } else {
        el.className = "invalid";
        el.innerHTML = '<span class="rule-icon">❌</span>' + el.innerText.substring(2);
    }
}

function validatePassword() {
    const pwd = document.getElementById("reg-password").value;
    const confirmPwd = document.getElementById("reg-password-confirm").value;
    const rulesBox = document.getElementById("password-rules");
    
    // Показываем блок с правилами, если начали вводить пароль
    if (pwd.length > 0) rulesBox.style.display = "block";
    else rulesBox.style.display = "none";

    // Проверяем правила
    const hasLength = pwd.length >= 8;
    const hasLetter = /[a-zA-Zа-яА-Я]/.test(pwd);
    const hasNumber = /\d/.test(pwd);
    const noSpaces = !/\s/.test(pwd) && pwd.length > 0; // <-- Проверка на отсутствие пробелов
    const isMatch = (pwd === confirmPwd) && (pwd.length > 0);

    updateRuleUI("rule-length", hasLength);
    updateRuleUI("rule-letter", hasLetter);
    updateRuleUI("rule-number", hasNumber);
    updateRuleUI("rule-space", noSpaces); // <-- Обновляем интерфейс
    updateRuleUI("rule-match", isMatch);

    // Кнопка сработает только если все 5 условий выполнены
    return hasLength && hasLetter && hasNumber && noSpaces && isMatch;
}

// --- 3. АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ ---

function parseError(errorData) {
    if (Array.isArray(errorData.detail)) return "Пожалуйста, проверьте правильность введенных данных.";
    return errorData.detail || "Неизвестная ошибка сервера";
}

async function register() {
    const u = document.getElementById("reg-username").value.trim();
    const p = document.getElementById("reg-password").value.trim();

    if (!u) { showMsg("message-auth", "Введите логин", "red"); return; }
    if (!validatePassword()) { showMsg("message-auth", "Пароль не соответствует требованиям", "red"); return; }

    setButtonLoading("btn-register", true, "Создать аккаунт");

    try {
        const response = await fetch("/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: u, password: p })
        });

        if (response.ok) {
            showMsg("message-auth", "Регистрация успешна! Выполните вход.", "green");
            switchTab('login'); // Автоматически переключаем на вкладку входа
            document.getElementById("login-username").value = u;
        } else {
            const error = await response.json();
            showMsg("message-auth", parseError(error), "red");
        }
    } catch (e) {
        showMsg("message-auth", "Ошибка сети", "red");
    } finally {
        setButtonLoading("btn-register", false, "Создать аккаунт");
    }
}

async function login() {
    const u = document.getElementById("login-username").value.trim();
    const p = document.getElementById("login-password").value.trim();

    if (!u || !p) { showMsg("message-auth", "Введите логин и пароль.", "red"); return; }

    setButtonLoading("btn-login", true, "Войти в систему");

    const formData = new URLSearchParams();
    formData.append("username", u);
    formData.append("password", p);

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData
        });

        if (response.ok) {
            const data = await response.json();
            if (data.mfa_required) {
                document.getElementById("loginMfaBlock").style.display = "block";
                showMsg("message-auth", data.message, "#4a90e2");
            } else {
                completeLogin(data.access_token);
            }
        } else {
            const error = await response.json();
            showMsg("message-auth", parseError(error), "red");
        }
    } catch (e) {
        showMsg("message-auth", "Ошибка соединения", "red");
    } finally {
        setButtonLoading("btn-login", false, "Войти в систему");
    }
}

async function loginWithMfa() {
    const u = document.getElementById("login-username").value.trim();
    const p = document.getElementById("login-password").value.trim();
    const code = document.getElementById("loginMfaCode").value.trim();

    if (!code || code.length !== 6) { showMsg("message-auth", "Код должен состоять из 6 цифр.", "red"); return; }

    setButtonLoading("btn-login-mfa", true, "Подтвердить вход");

    const formData = new URLSearchParams();
    formData.append("username", u);
    formData.append("password", p);
    formData.append("mfa_code", code);

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData
        });

        if (response.ok) {
            const data = await response.json();
            completeLogin(data.access_token);
        } else {
            const error = await response.json();
            showMsg("message-auth", parseError(error), "red");
        }
    } catch (e) {
        showMsg("message-auth", "Ошибка сети", "red");
    } finally {
        setButtonLoading("btn-login-mfa", false, "Подтвердить вход");
    }
}

function completeLogin(token) {
    localStorage.setItem("jwt_token", token);
    checkAuthStatus();
    showMsg("message-dash", "Успешный вход!", "green");
}

function logout() {
    localStorage.removeItem("jwt_token");
    showMsg("message-auth", "Вы успешно вышли из системы", "green");
    checkAuthStatus();
}

// --- 4. ЗАЩИЩЕННЫЕ ОПЕРАЦИИ (ЛИЧНЫЙ КАБИНЕТ) ---

async function getSecretData() {
    const token = localStorage.getItem("jwt_token");
    const response = await fetch("/protected_data", {
        method: "GET",
        headers: { "Authorization": "Bearer " + token }
    });

    if (response.ok) {
        const data = await response.json();
        showMsg("message-dash", "Доступ разрешен: " + data.message, "green");
    } else {
        logout();
        showMsg("message-auth", "Сессия истекла. Войдите заново.", "red");
    }
}

async function setupMFA() {
    const token = localStorage.getItem("jwt_token");
    const response = await fetch("/mfa/setup", {
        method: "GET",
        headers: { "Authorization": "Bearer " + token }
    });

    if (response.ok) {
        const data = await response.json();
        document.getElementById("mfaSetupBlock").style.display = "block";
        document.getElementById("qrCodeImage").src = data.qr_code_url;
        document.getElementById("qrCodeImage").style.display = "block";
    } else {
        const error = await response.json();
        showMsg("message-dash", "Внимание: " + error.detail, "red");
    }
}

async function verifyMFA() {
    const token = localStorage.getItem("jwt_token");
    const code = document.getElementById("mfaCode").value;
    
    setButtonLoading("btn-verify-mfa", true, "Подтвердить привязку");

    try {
        const response = await fetch("/mfa/verify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token
            },
            body: JSON.stringify({ code: code })
        });

        if (response.ok) {
            const data = await response.json();
            showMsg("message-dash", data.message, "green");
            document.getElementById("mfaSetupBlock").style.display = "none";
            document.getElementById("mfaCode").value = "";
        } else {
            const error = await response.json();
            showMsg("message-dash", error.detail, "red");
        }
    } catch (e) {
        showMsg("message-dash", "Ошибка сети", "red");
    } finally {
        setButtonLoading("btn-verify-mfa", false, "Подтвердить привязку");
    }
}