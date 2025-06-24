1

{% extends 'base.html' %} {% block title %}Тест 4: Фішинг{% endblock %} {% block
content %}

<div class="alert alert-primary">
  <b>Ваша історія:</b> Ви — вчитель у школі. Кінець навчального року —
  напружений час, ви отримуєте багато листів на свою робочу електронну скриньку.
  Серед відправників — і колеги, і адміністрація, і навіть учні. У цей період
  легко пропустити щось важливе або стати жертвою фішингу. Ваше завдання:
  <b
    >переглянути кілька листів і відмітити ті, які здаються вам підозрілими або
    фішинговими.</b
  >
</div>

<div class="alert alert-warning">
  <b>УВАГА!</b> Це навчальна імітація фішингу. Не переходьте за підозрілими
  посиланнями і не вводьте своїх реальних даних!
</div>

<h2>Тест 4: Виявлення фішингових листів</h2>
<p>
  Ознайомтеся з листами нижче та відмітьте ті, які вважаєте фішинговими
  (фейковими). Після перевірки система дасть підказки!
</p>

<form method="post">
  <div class="list-group">
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="0" />
      <b>Від:</b> admin@school.edu.ua<br />
      <b>Тема:</b> Важливе оновлення системи оцінювання<br />
      <b>Текст:</b> Шановний(а) вчителю, для оновлення вашого акаунта терміново
      перейдіть за <a href="#">цим посиланням</a> та введіть свої дані.
    </div>
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="1" />
      <b>Від:</b> director@school.edu.ua<br />
      <b>Тема:</b> Підсумкова педрада<br />
      <b>Текст:</b> Нагадуємо, що підсумкова педагогічна рада відбудеться у
      п’ятницю о 15:00 в актовій залі.
    </div>
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="2" />
      <b>Від:</b> pupil231@gmail.com<br />
      <b>Тема:</b> Моя оцінка за контрольну<br />
      <b>Текст:</b> Доброго дня! Я бачив(ла), що моя оцінка ще не виставлена,
      могли б ви перевірити?
    </div>
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="3" />
      <b>Від:</b> info@admin-school.com<br />
      <b>Тема:</b> Ваша пошта буде заблокована!<br />
      <b>Текст:</b> Для уникнення блокування негайно авторизуйтеся
      <a href="#">за цим посиланням</a>.
    </div>
  </div>
  <button type="submit" class="btn btn-primary mt-3">Перевірити</button>
</form>
{% if result %}
<div class="alert alert-info mt-3">{{ result }}</div>
{% endif %} {% if details %}
<div class="alert alert-secondary mt-2">{{ details|safe }}</div>
{% endif %} {% endblock %}







============================================


2

{% extends 'base.html' %} {% block title %}Тест 4: Фішинг{% endblock %} {% block
content %}

<div class="alert alert-warning">
  <b>УВАГА!</b> Це навчальна імітація фішингу. Не переходьте за підозрілими
  посиланнями і не вводьте своїх реальних даних!
</div>

<h2>Тест 4: Виявлення фішингових листів</h2>
<p>
  Ознайомтеся з трьома ситуаціями нижче та відмічайте фішингові листи у кожній.
</p>

<hr />
<h4>Історія 1: Вчитель у школі</h4>
<div class="alert alert-primary">
  Ви — вчитель. Наприкінці навчального року отримуєте багато листів. Ваше
  завдання: знайти фішингові.
</div>
<form method="post">
  <input type="hidden" name="story" value="1" />
  <div class="list-group">
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="0" />
      <b>Від:</b> admin@school.edu.ua<br />
      <b>Тема:</b> Оновлення системи оцінювання<br />
      <b>Текст:</b> Перейдіть за <a href="#">посиланням</a> і введіть свої дані.
    </div>
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="1" />
      <b>Від:</b> pupil231@gmail.com<br />
      <b>Тема:</b> Контрольна робота<br />
      <b>Текст:</b> Чи могли б ви виставити оцінку?
    </div>
  </div>
  <button type="submit" class="btn btn-primary mt-3">Перевірити</button>
</form>

<hr />
<h4>Історія 2: ІТ-спеціаліст в офісі</h4>
<div class="alert alert-primary">
  Ви — ІТ-фахівець компанії. Щодня отримуєте багато технічних запитів. Визначте
  потенційно небезпечні листи.
</div>
<form method="post">
  <input type="hidden" name="story" value="2" />
  <div class="list-group">
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="0" />
      <b>Від:</b> hr@company.com<br />
      <b>Тема:</b> Нові правила для пошти<br />
      <b>Текст:</b> Ознайомтеся з новими правилами. <a href="#">Перейти</a>
    </div>
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="1" />
      <b>Від:</b> it-admin@companny.com<br />
      <b>Тема:</b> Термінова перевірка<br />
      <b>Текст:</b> Ваша пошта буде заблокована.
      <a href="#">Підтвердити</a> зараз!
    </div>
  </div>
  <button type="submit" class="btn btn-primary mt-3">Перевірити</button>
</form>

<hr />
<h4>Історія 3: Бухгалтер в університеті</h4>
<div class="alert alert-primary">
  Ви — бухгалтер. У вас багато листів від постачальників і співробітників.
  Знайдіть підозрілі.
</div>
<form method="post">
  <input type="hidden" name="story" value="3" />
  <div class="list-group">
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="0" />
      <b>Від:</b> finance@univ.edu.ua<br />
      <b>Тема:</b> Підтвердження платежу<br />
      <b>Текст:</b> Перевірте вкладення перед підписанням документу.
    </div>
    <div class="list-group-item">
      <input type="checkbox" name="phish" value="1" />
      <b>Від:</b> supplier@un1v-bill.com<br />
      <b>Тема:</b> Заборгованість по рахунку<br />
      <b>Текст:</b> Натисніть <a href="#">тут</a>, щоб погасити заборгованість.
    </div>
  </div>
  <button type="submit" class="btn btn-primary mt-3">Перевірити</button>
</form>

{% if result %}
<div class="alert alert-info mt-3">{{ result }}</div>
{% endif %} {% if details %}
<div class="alert alert-secondary mt-2">{{ details|safe }}</div>
{% endif %} {% endblock %}
