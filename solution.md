# Задача 20:
[Загрузить папку проекта](https://github.com/deathofthedivine/knit241/raw/refs/heads/main/PasswordManager.7z)
## Реализовано:
* Менеджер Паролей с использованием Spring Context, позволяющий шифровать и хранить пароли для нескольких ресурсов
* Шифрование через AES
* Логгирование действий пользователя 
* Сохранение и загрузка данных в файл
* Мульти-пользователь
* Асинхронная очистка буфера обмена

## Структура проекта:
![image](https://github.com/user-attachments/assets/0d6d217a-15f1-4f73-813e-585a34ed9d07)

## Код проекта:
### `App.java`:
Точка входа в приложение. Отвечает за главный цикл программы, обработку комманд, вводимых пользователем.
<details>
<summary>Код.</summary>

```
package com.idk.passwordmanager;

import com.idk.passwordmanager.config.AppConfig;
import com.idk.passwordmanager.security.MasterPasswordHolder;
import com.idk.passwordmanager.security.UserIdentifier;
import com.idk.passwordmanager.service.PasswordService;
import com.idk.passwordmanager.storage.EncryptedFileStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import java.util.Arrays;
import java.util.Scanner;

public class App {
    private static final Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext(AppConfig.class);
        MasterPasswordHolder masterPasswordHolder = ctx.getBean(MasterPasswordHolder.class);
        PasswordService svc = ctx.getBean(PasswordService.class);
        EncryptedFileStorage store = ctx.getBean(EncryptedFileStorage.class);

        Runtime.getRuntime().addShutdownHook(new Thread(ctx::close));

        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\n--- Password Manager ---");
            System.out.print("Введите мастер-пароль (или 'exit' для выхода): ");
            char[] masterPassword;
            if (System.console() != null) {
                masterPassword = System.console().readPassword();
            } else {
                masterPassword = scanner.nextLine().toCharArray();
            }

            if (new String(masterPassword).equalsIgnoreCase("exit")) {
                break;
            }

            masterPasswordHolder.setPassword(masterPassword);
            String userId = UserIdentifier.generate(masterPassword);

            try {
                svc.load(store.load(userId));
                log.info("Успешный вход для пользователя с ID: {}", userId);
                System.out.println("Хранилище успешно загружено. Добро пожаловать!");
            } catch (Exception e) {
                log.error("Не удалось войти для пользователя {}: {}", userId, e.getMessage());
                System.out.println("ОШИБКА: Не удалось расшифровать хранилище. Проверьте мастер-пароль.");
                masterPasswordHolder.clear();
                Arrays.fill(masterPassword, '\0');
                continue;
            }

            boolean loggedIn = true;
            while (loggedIn) {
                System.out.print(userId.substring(0, 6) + "@vault > ");
                String line = scanner.nextLine();
                String[] cmd = line.split(" ", 2);

                try {
                    switch (cmd[0]) {
                        case "add" -> {
                            System.out.print("site: "); String site = scanner.nextLine();
                            System.out.print("login: "); String login = scanner.nextLine();
                            System.out.print("password: "); String pwd = scanner.nextLine();
                            svc.add(site, login, pwd);
                            store.save(userId, svc.getAll());
                            System.out.println("Запись добавлена.");
                        }
                        case "list" -> svc.list();
                        case "copy" -> {
                            if (cmd.length < 2) { System.out.println("Укажите сайт: copy <site>"); continue; }
                            svc.copy(cmd[1]);
                            System.out.println("Пароль для '" + cmd[1] + "' скопирован в буфер обмена на 30 секунд.");
                        }
                        case "delete" -> {
                            if (cmd.length < 2) { System.out.println("Укажите сайт: delete <site>"); continue; }
                            svc.delete(cmd[1]);
                            store.save(userId, svc.getAll());
                            System.out.println("Запись для '" + cmd[1] + "' удалена.");
                        }
                        case "logout" -> {
                            loggedIn = false;
                            System.out.println("Выход из текущего хранилища...");
                        }
                        case "exit" -> {
                            System.out.println("Завершение работы...");
                            System.exit(0);
                        }
                        default -> System.out.println("Команды: add, list, copy, delete, logout, exit");
                    }
                } catch (Exception e) {
                    log.error("Ошибка при выполнении команды '{}'", line, e);
                    System.out.println("Произошла ошибка: " + e.getMessage());
                }
            }
            masterPasswordHolder.clear();
            Arrays.fill(masterPassword, '\0');
        }

        System.out.println("Работа приложения завершена.");
    }
}
```

</details>

### `AppConfig.java`:
Конфигурация Spring. С помощью аннотаций @Configuration и @Bean я описываю, какие компоненты должны быть в приложении и как они зависят друг от друга. 
<details>
<summary>Код.</summary>

```
package com.idk.passwordmanager.config;

import com.idk.passwordmanager.clipboard.*;
import com.idk.passwordmanager.crypto.*;
import com.idk.passwordmanager.repository.*;
import com.idk.passwordmanager.security.*;
import com.idk.passwordmanager.service.*;
import com.idk.passwordmanager.storage.*;
import org.springframework.context.annotation.*;

@Configuration
public class AppConfig {
    @Bean
    public MasterPasswordHolder masterPasswordHolder() {
        return new MasterPasswordHolder();
    }

    @Bean
    public EncryptionService enc(MasterPasswordHolder m) {
        return new AesEncryptionService(m);
    }

    @Bean
    public ClipboardService cb() {
        return new SystemClipboardService();
    }

    @Bean
    public PasswordRepository repo() {
        return new InMemoryPasswordRepository();
    }

    @Bean
    public PasswordService svc(PasswordRepository r, EncryptionService e, ClipboardService c) {
        return new PasswordService(r, e, c);
    }

    @Bean
    public EncryptedFileStorage storage(EncryptionService e) {
        return new EncryptedFileStorage(e);
    }
}
```

</details>


### `PasswordEntry.java`:
Класс для хранения и передачи полей сайта, логина и пароля между слоями приложентя.
<details>
<summary>Код.</summary>

```
package com.idk.passwordmanager.model;

public class PasswordEntry {
    public String site;
    public String login;
    public String encryptedPassword;

    public PasswordEntry() {}
    public PasswordEntry(String site, String login, String encryptedPassword) {
        this.site = site;
        this.login = login;
        this.encryptedPassword = encryptedPassword;
    }
}

```

</details>

### `repository`: `PasswordRepository.java` и `InMemoryPasswordRepository.java`
* `PasswordRepository.java` - интерфейс, описывает возможные методы менеджера паролей
* `InMemoryPasswordRepository.java` - реализация репозитория в ОЗУ
<details>
<summary>Код (PasswordRepository.java)</summary>

```
package com.idk.passwordmanager.repository;

import com.idk.passwordmanager.model.PasswordEntry;
import java.util.*;

public interface PasswordRepository {
    void add(PasswordEntry e);
    void delete(String site);
    PasswordEntry get(String site);
    List<PasswordEntry> getAll();
    void setAll(List<PasswordEntry> entries);
}

```

</details>

<details>
<summary>Код (InMemoryPasswordRepository.java)</summary>

```
package com.idk.passwordmanager.repository;

import com.idk.passwordmanager.model.PasswordEntry;
import java.util.*;

public class InMemoryPasswordRepository implements PasswordRepository {
    private final Map<String, PasswordEntry> m = new HashMap<>();

    public void add(PasswordEntry e) { m.put(e.site, e); }
    public void delete(String site) { m.remove(site); }
    public PasswordEntry get(String site) { return m.get(site); }
    public List<PasswordEntry> getAll() { return new ArrayList<>(m.values()); }
    public void setAll(List<PasswordEntry> l) {
        m.clear();
        for (PasswordEntry e : l) m.put(e.site, e);
    }
}

```

</details>

### `PasswordService.java`:
Класс, содержащий в себе методы, доступные пользователю (`add`, `delete`, `copy`, `list`)
<details>
<summary>Код.</summary>

```
package com.idk.passwordmanager.service;

import com.idk.passwordmanager.model.PasswordEntry;
import com.idk.passwordmanager.repository.PasswordRepository;
import com.idk.passwordmanager.crypto.EncryptionService;
import com.idk.passwordmanager.clipboard.ClipboardService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordService {
    private final PasswordRepository repo;
    private final EncryptionService enc;
    private final ClipboardService cb;
    private final Logger log = LoggerFactory.getLogger(PasswordService.class);

    public PasswordService(PasswordRepository r, EncryptionService e, ClipboardService c) {
        repo = r; enc = e; cb = c;
    }

    public void add(String site, String login, String pwd) {
        repo.add(new PasswordEntry(site, login, enc.encrypt(pwd)));
        log.info("add {}", site);
    }

    public void delete(String site) {
        repo.delete(site);
        log.info("delete {}", site);
    }

    public void copy(String site) {
        var e = repo.get(site);
        if (e == null) throw new RuntimeException("not found");
        cb.copy(enc.decrypt(e.encryptedPassword));
        log.info("copy {}", site);
    }

    public void list() {
        for (var e : repo.getAll())
            System.out.println(e.site + " - " + e.login);
    }

    public java.util.List<PasswordEntry> getAll() {
        return repo.getAll();
    }

    public void load(java.util.List<PasswordEntry> l) {
        repo.setAll(l);
    }
}


```

</details>

### `crypto`: `EncryptionService.java` и `AesEncryptionService.java`:
* `EncryptionService.java` - определяет методы `encrypt` и `decrypt`
* `AesEncryptionService.java` - реализует шифрование по стандарту AES. Ключ генерируется из мастер-пароля с помощью алгоритма PBKDF2.
<details>
<summary>Код (EncryptionService.java)</summary>

```
package com.idk.passwordmanager.crypto;

public interface EncryptionService {
    String encrypt(String raw);
    String decrypt(String enc);
}

```

</details>

<details>
<summary>Код (AesEncryptionService.java)</summary>

```
package com.idk.passwordmanager.crypto;

import com.idk.passwordmanager.security.MasterPasswordHolder;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public class AesEncryptionService implements EncryptionService {
    private static final String ALGO = "AES/CBC/PKCS5Padding";
    private static final String KEY_FACTORY_ALGO = "PBKDF2WithHmacSHA256";
    private static final int IV_LENGTH = 16;
    private static final int SALT_LENGTH = 16;

    private final MasterPasswordHolder masterPasswordHolder;
    private final SecureRandom secureRandom = new SecureRandom();

    public AesEncryptionService(MasterPasswordHolder holder) {
        this.masterPasswordHolder = holder;
    }

    private SecretKey getKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY_ALGO);
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    @Override
    public String encrypt(String raw) {
        try {
            byte[] salt = new byte[SALT_LENGTH];
            secureRandom.nextBytes(salt);

            SecretKey secretKey = getKey(masterPasswordHolder.get(), salt);

            byte[] iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(raw.getBytes());

            byte[] output = new byte[SALT_LENGTH + IV_LENGTH + encrypted.length];
            System.arraycopy(salt, 0, output, 0, SALT_LENGTH);
            System.arraycopy(iv, 0, output, SALT_LENGTH, IV_LENGTH);
            System.arraycopy(encrypted, 0, output, SALT_LENGTH + IV_LENGTH, encrypted.length);

            return Base64.getEncoder().encodeToString(output);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @Override
    public String decrypt(String encryptedString) {
        try {
            byte[] data = Base64.getDecoder().decode(encryptedString);

            byte[] salt = Arrays.copyOfRange(data, 0, SALT_LENGTH);
            byte[] iv = Arrays.copyOfRange(data, SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
            byte[] encrypted = Arrays.copyOfRange(data, SALT_LENGTH + IV_LENGTH, data.length);

            SecretKey secretKey = getKey(masterPasswordHolder.get(), salt);

            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            return new String(cipher.doFinal(encrypted));
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}

```

</details>

### `security`: `MasterPasswordHolder.java` и `UserIdentifier.java`:
* `MasterPasswordHolder.java` - хранит мастер-пароль в массиве char[]. 
* `UserIdentifier.java` - реализацция мульти-пользователя. Создаёт идентификатор пользователя путём хеширования его мастер-пароля. 
<details>
<summary>Код (MasterPasswordHolder.java)</summary>

```
package com.idk.passwordmanager.security;

import java.util.Arrays;

public class MasterPasswordHolder {
    private char[] password;

    public MasterPasswordHolder() {
        this.password = null;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }

    public char[] get() {
        return password;
    }

    public void clear() {
        if (password != null) {
            Arrays.fill(password, '\0');
            password = null;
        }
    }
}

```

</details>
<details>
<summary>Код (UserIdentifier.java)</summary>

```
package com.idk.passwordmanager.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class UserIdentifier {

    private static final byte[] IDENTIFIER_SALT = "a-very-fixed-salt-for-user-id".getBytes();
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    public static String generate(char[] masterPassword) {
        try {
            KeySpec spec = new PBEKeySpec(masterPassword, IDENTIFIER_SALT, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Could not generate user identifier", e);
        }
    }
}

```

</details>

### `clipboard`: `ClipboardService.java` и `SystemClipboardService.java`:
* `ClipboardService.java` - интерфейс для копирования текста
* `SystemClipboardService.java` - использует `java.awt.Toolkit` для доступа к системному буферу обмена, автоматически удаляеи пароль из буфера обмена через 30 секунд
<details>
<summary>Код (ClipboardService.java)</summary>

```
package com.idk.passwordmanager.clipboard;

public interface ClipboardService {
    void copy(String text);
}
```

</details>

<details>
<summary>Код (ClipboardService.java)</summary>

```
package com.idk.passwordmanager.clipboard;

import java.awt.*;
import java.awt.datatransfer.*;
import java.util.concurrent.*;

public class SystemClipboardService implements ClipboardService {
    public void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(text), null);
        ScheduledExecutorService ex = Executors.newSingleThreadScheduledExecutor();
        ex.schedule(() -> {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(""), null);
            ex.shutdown();
        }, 30, TimeUnit.SECONDS);
    }
}
```

</details>

### `EncryptedFileStorage.java`:
Отвечает за сохранение и загрузку данных между сессиями.
<details>
<summary>Код</summary>

```
package com.idk.passwordmanager.storage;

import com.fasterxml.jackson.core.type.TypeReference;
import com.idk.passwordmanager.crypto.EncryptionService;
import com.idk.passwordmanager.model.PasswordEntry;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;

public class EncryptedFileStorage {
    private final File storageFile = new File("master_vault.json");
    private final ObjectMapper mapper = new ObjectMapper();
    private final EncryptionService encryptionService;

    public EncryptedFileStorage(EncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    public List<PasswordEntry> load(String userId) {
        Map<String, String> vault = loadVault();
        String encryptedData = vault.get(userId);

        if (encryptedData == null || encryptedData.isEmpty()) {
            return new ArrayList<>();
        }

        try {
            String json = encryptionService.decrypt(encryptedData);
            return mapper.readValue(json, new TypeReference<>() {});
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt data. Master password may be incorrect.", e);
        }
    }

    public void save(String userId, List<PasswordEntry> entries) {
        Map<String, String> vault = loadVault();
        try {
            String json = mapper.writeValueAsString(entries);
            String encryptedData = encryptionService.encrypt(json);
            vault.put(userId, encryptedData);

            Files.write(storageFile.toPath(), mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(vault));
        } catch (Exception e) {
            throw new RuntimeException("Failed to save data.", e);
        }
    }

    private Map<String, String> loadVault() {
        if (!storageFile.exists()) {
            return new HashMap<>();
        }
        try {
            byte[] fileBytes = Files.readAllBytes(storageFile.toPath());
            if (fileBytes.length == 0) {
                return new HashMap<>();
            }
            return mapper.readValue(fileBytes, new TypeReference<>() {});
        } catch (IOException e) {
            return new HashMap<>();
        }
    }
}
```

</details>

## Скриншоты работы программы:
![image](https://github.com/user-attachments/assets/f45faa11-f875-4099-86a2-bf240d060775)
![image](https://github.com/user-attachments/assets/71198242-7d63-4907-a04c-19107a397e21)
![image](https://github.com/user-attachments/assets/8a02959a-90b6-4072-955f-9ef52fe78a26)

# Задача 21:
## Ход работы:
### Шаг 1:
![image](https://github.com/user-attachments/assets/928fdbbc-dd20-4e7f-beab-ffbbee5903fb)
### Шаг 2:
![image](https://github.com/user-attachments/assets/d2f1fc3a-68f8-4064-9d25-fc31f1c81172)  
У меня оказался закоррапчен PATH.
![image](https://github.com/user-attachments/assets/cee629d0-539c-4e8d-b5c0-7a87c6da3f43)
### Шаг 3:
![image](https://github.com/user-attachments/assets/83a77d7f-1acf-41b9-9c1e-e6a6633d4169)
### Шаг 4:
![image](https://github.com/user-attachments/assets/429c2c12-6648-4654-b4f8-e78fc6695e8c)  
Прописал другой порт.  
![image](https://github.com/user-attachments/assets/32be15cf-9358-42ac-a967-f56c484476fa)
![image](https://github.com/user-attachments/assets/c55d8724-ae8f-4c32-99c6-9e44268fa27c)
![image](https://github.com/user-attachments/assets/9e87fbca-367b-4f8c-880b-127fc2153314)
![image](https://github.com/user-attachments/assets/8890eae1-06dd-45dd-a4bd-7a6f1b8f611d)
### Шаг 5 (Логгирование):
![image](https://github.com/user-attachments/assets/7e4ba039-a775-4245-af40-f306f698b028)
![image](https://github.com/user-attachments/assets/aae3b7d7-6b0f-4aae-99de-7025ce66e925)

# Задача 22:
## Ход работы:
### Шаг 1:
![image](https://github.com/user-attachments/assets/2e0c314b-b3e6-4c5d-b386-6ecf3aa34073)
![image](https://github.com/user-attachments/assets/de8f3794-f79a-41a9-bbad-49c3ddf97dc9)

### Шаги 2-4:
Новая структура проекта:  
![image](https://github.com/user-attachments/assets/9ca40520-a567-4bbd-aa93-ada23fa4a250)

### Шаг 5:
* Все города:
![image](https://github.com/user-attachments/assets/c7d8387d-7674-45b9-ac81-6968d5c39423)
* Один город по имени:
![image](https://github.com/user-attachments/assets/e2cf8382-c5b5-451e-8fe3-777055dffc9a)

# Задача 23:
[Загрузить папку проекта](https://github.com/deathofthedivine/knit241/raw/refs/heads/main/website.7z)
## Главная страница:
![image](https://github.com/user-attachments/assets/b8d07ea3-726a-43db-92ac-23b20db69fde)
## Поиск:
![image](https://github.com/user-attachments/assets/4fabf8f1-dd07-4e8e-8daf-9594d6163bdb)
![image](https://github.com/user-attachments/assets/06cef12b-4489-46bb-8b8c-675b9f8f0ab2)
![image](https://github.com/user-attachments/assets/2bb1f9da-b959-4abb-8172-86cd4944cefe)
## Страница города:
![image](https://github.com/user-attachments/assets/744858fa-d95d-43cb-921c-d5e014ecbe3a)
## Страница "О проекте":
![image](https://github.com/user-attachments/assets/cc22f1a1-582c-4aa4-957e-83c23a442b16)
## Страница ошибки:
![image](https://github.com/user-attachments/assets/917eec66-9b76-4816-ab76-d578931dea0b)
