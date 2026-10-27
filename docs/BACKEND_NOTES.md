# Замечания по backend (не применены, код платформы не менялся)

Проверено чтением `app/main.py` и `app/models.py`, а также автотестами стыков (`tests/test_integration.py`).
Сам backend и его `tests/test_backend.py` в этой проверке не запускались.

## Желательные правки

1. **Гости получают сырой JSON 401** на `/challenges`, `/profile`, `/admin`, а пользователь с начальным паролем получает 403.
   Для страниц лучше перенаправлять:

   ```python
   from fastapi.exceptions import HTTPException as StarletteHTTPException
   from fastapi.responses import RedirectResponse

   @app.exception_handler(StarletteHTTPException)
   async def redirect_to_login(request, exc):
       accepts_html = "text/html" in request.headers.get("accept", "")
       if accepts_html and request.method == "GET":
           if exc.status_code == 401:
               return RedirectResponse("/login", status_code=303)
           if exc.status_code == 403 and exc.detail == "Please change initial password":
               return RedirectResponse("/change-password", status_code=303)
       return await http_exception_handler(request, exc)   # from fastapi.exception_handlers import http_exception_handler
   ```

2. **Ограничение попыток считается по паре «пользователь + задание»** и содержит гонку при параллельных запросах.
   Достаточно для MVP, но можно считать по пользователю и делать проверку и запись в одной транзакции.
3. **`resource_url` не валидируется.** Шаблон показывает ссылку только если она начинается с `/`;
   в `validate_challenge` стоит добавить такую же проверку.
4. **Нет ограничения попыток входа в приложении.** Закрыто только запасным лимитом Nginx.
5. **Пароль при регистрации от 10 символов, при смене от 12.** Лучше единое правило.

## Что нужно знать команде

- Хеш флага это HMAC-SHA256 с `SECRET_KEY`. Смена `SECRET_KEY` делает все хеши недействительными.
  Задания загружает `app/seed_challenges.py` по этой же формуле (проверено тестом против реальной `hash_flag()`).
- Статику (`/static/...`) раздаёт Nginx, в `main.py` её монтировать не нужно.
