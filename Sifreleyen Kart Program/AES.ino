#include <Crypto.h>
#include <AES.h>
#include <SHA256.h>
#include <string.h>
#include <FirebaseESP8266.h>
#include <ESP8266WiFi.h>

#define FIREBASE_HOST "aes-iot-default-rtdb.europe-west1.firebasedatabase.app" // http:// veya https:// olmadan yazın
#define FIREBASE_AUTH "UjoD8R7hSSCA5AkNnw38NToAH8Oo93na9n952cPK"

#define WIFI_SSID "Ibrahim"
#define WIFI_PASSWORD "123456aaaa"

#define HASH_SIZE 32
#define BLOCK_SIZE 64

FirebaseData firebaseData;
String SifreliMetin;
int yontem = 0;
String inputString = "";
String yontemString = "";
String hashString = "";
boolean yontemComplete = false;
boolean stringComplete = false;
boolean yazdim = false;
boolean yazdimIki = false;
unsigned long elapsed;
unsigned long elapsedKey;
unsigned long elapsedHash;
int cycle = 0;


struct TestVector
{
  const char *name;
  byte key[32];
  byte plaintext[16];
  byte ciphertext[16];
};

struct TestHashVector
{
  const char *name;
  const char *key;
  char *data;
  uint8_t hash[HASH_SIZE];
};

static TestVector testVectorAES128 = {
  .name        = "AES-128-ECB",
  .key         = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
  },
  .plaintext   = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
  },
  .ciphertext  = {
    0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
    0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A
  }
};
static TestVector testVectorAES192 = {
  .name        = "AES-192-ECB",
  .key         = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
  },
  .plaintext   = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
  },
  .ciphertext  = {
    0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0,
    0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91
  }
};
static TestVector testVectorAES256 = {
  .name        = "AES-256-ECB",
  .key         = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  },
  .plaintext   = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
  },
  .ciphertext  = {
    0x07, 0xc7, 0x2c, 0x18, 0x5c, 0x7F, 0xed, 0xee,
    0x0e, 0xfd, 0xdf, 0x4f, 0x63, 0x91, 0x2c, 0xa1
  }
};

static TestHashVector testVectorSHA256 = {
  "SHA-256 #1",
  0,
  "abc",
  { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
  }
};

AES128 aes128;
AES192 aes192;
AES256 aes256;
SHA256 sha256;

byte buffer[16];
byte bufferHash[128];

void testCipher(BlockCipher *cipher, const struct TestVector *test)
{
  Serial.print("Şifreleme Tipi:");
  Serial.println(test->name);
  Serial.print("Acik Metin:");
  for (int i = 0; i < sizeof(test->plaintext); i++) Serial.print(test->plaintext[i], HEX);
  Serial.println();
  Serial.print("Anahtar:");
  for (int i = 0; i < sizeof(test->key); i++) Serial.print(test->key[i], HEX);
  Serial.println();
  Serial.print("Encryption ... ");
  Serial.println();
  cipher->setKey(test->key, cipher->keySize());
  cipher->encryptBlock(buffer, test->plaintext);
  Serial.print("Sifrelenmis Metin:");
  for (int i = 0; i < sizeof(buffer); i++) {
    Serial.print(buffer[i], HEX);
    SifreliMetin += (String(buffer[i] , HEX).length() < 2 ? "0" + String(buffer[i] , HEX) : String(buffer[i] , HEX));
    Serial.print(",");
  }
  Serial.println();
}

void perfCipher(BlockCipher *cipher, const struct TestVector *test)
{
  unsigned long start;
  int count;
  start = micros();
  for (count = 0; count < 10000; ++count) {
    cipher->setKey(test->key, cipher->keySize());
  }
  elapsedKey += micros() - start;

  start = micros();
  for (count = 0; count < 5000; ++count) {
    cipher->encryptBlock(buffer, buffer);
  }
  elapsed += micros() - start;
}

bool testHash_N(Hash *hash, const struct TestHashVector *test, size_t inc)
{
  size_t size = strlen(test->data);
  size_t posn, len;
  uint8_t value[HASH_SIZE];


  hash->reset();
  for (posn = 0; posn < size; posn += inc) {
    len = size - posn;
    if (len > inc)
      len = inc;
    if (inc == 64) {
      unsigned long start;
      int count;
      start = micros();
      for (count = 0; count < 500; ++count) {
        hash->update(test->data + posn, len);
      }
      elapsedHash = micros() - start;
    } else {
      hash->update(test->data + posn, len);
    }
  }
  hash->finalize(value, sizeof(value));
  if (inc == 64) {
    hashString = "";
    for (int i = 0; i < HASH_SIZE; i++) {
      Serial.print(value[i], HEX);
      hashString.concat(value[i]);
    }
    Serial.println();
  }
  return true;
}

void testHash(Hash *hash, const struct TestHashVector *test)
{
  bool ok;

  Serial.print(test->name);
  Serial.println(" ... ");

  ok  = testHash_N(hash, test, strlen(test->data));
  ok &= testHash_N(hash, test, 1);
  ok &= testHash_N(hash, test, 2);
  ok &= testHash_N(hash, test, 5);
  ok &= testHash_N(hash, test, 8);
  ok &= testHash_N(hash, test, 13);
  ok &= testHash_N(hash, test, 16);
  ok &= testHash_N(hash, test, 24);
  ok &= testHash_N(hash, test, 63);
  ok &= testHash_N(hash, test, 64);
}

void setup()
{
  Serial.begin(115200);
  delay(1000);
  Serial.println();
  Serial.print("\nAğ Bağlantısı oluşturuluyor");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED)
  {
    Serial.print(".");
    delay(300);
  }
  Serial.println();
  Serial.print("IP adresine bağlanıldı: ");
  Serial.println(WiFi.localIP());
  Serial.println();
  Firebase.begin(FIREBASE_HOST, FIREBASE_AUTH);
  Firebase.reconnectWiFi(true);
  delay(1000);
}


void loop()
{
  if (yontemComplete == false) {
    if (yazdim == false) {
      Serial.println("Şireleme Yöntemi girin \n a: AES128 \n b: AES192 \n c: AES256");
      yazdim = true;
    }
    delay(5000);
    while (Serial.available()) {
      char inChare = (char)Serial.read();
      yontemString += inChare;
      if (inChare == '\n') {
        yontemComplete = true;
      }
    }
  }
  if (yontemComplete) {
    if (yontemString == "a\n") {
      delay(5000);
      if (yazdimIki == false) {
        Serial.println("Şirelenecek metni girin");
        yazdimIki = true;
      }
      while (Serial.available()) {
        char inChar = (char)Serial.read();
        if (inChar == '\n') {
          stringComplete = true;
        } else {
          inputString += inChar;
        }
      }
      hashString = inputString;
      // seri porttan gelen metin tamamlandıysa işlemleri yap
      if (stringComplete) {
        for (int i = 0; i < (hashString.length()); i++ ) {
          testVectorSHA256.data[i] = hashString.charAt(i);
          if (hashString.length() - 1 == i) {
            testVectorSHA256.data[i + 1] = '\0';
          }
        }
        Serial.println();
        testHash(&sha256, &testVectorSHA256);
        while ((inputString.length()) % 16 != 0) {
          inputString.concat("0");
        }
        // seri porttan gelen metni ekrana yazdır
        Serial.println("Gelen metin: " + inputString);
        for (int j = 0; j < ((inputString.length() - 1) / 16); j++) {
          for (int i = 0; i < 16; i++) {
            testVectorAES128.plaintext[i] = inputString.charAt(i + (j * 16)); // her karakter byte dizisine atanıyor
          }
          testCipher(&aes128, &testVectorAES128);
          perfCipher(&aes128, &testVectorAES128);
          cycle = j + 1;
        }
        yontem = 128;
        if (Firebase.setInt(firebaseData, "/yontem", yontem)) {
          delay(1000);
        } else {
          Serial.println(firebaseData.errorReason());
        }

        if (Firebase.setString(firebaseData, "/mesaj", SifreliMetin)) {
          delay(1000);
        } else {
          Serial.println(firebaseData.errorReason());
        }
        Serial.println();
        Serial.print("Performans verileri:");
        Serial.print(elapsed / (5000.0 * 16.0 * cycle));
        Serial.print("us per byte, ");
        Serial.print((16.0 * 5000.0 * 1000000.0 * cycle) / elapsed);
        Serial.println(" bytes per second");
        Serial.println();
        Serial.print("Set Key:");
        Serial.print(elapsedKey / (cycle * 10000.0));
        Serial.print("us per operation, ");
        Serial.print((10000.0 * 1000000.0 * cycle) / elapsedKey);
        Serial.println(" per second");
        Serial.println();
        Serial.print(elapsedHash / (sizeof(bufferHash) * 500.0));
        Serial.print("us per byte, ");
        Serial.print((sizeof(bufferHash) * 500.0 * 1000000.0) / elapsedHash);
        Serial.println(" bytes per second");
        Serial.println();
        SifreliMetin = "";
        inputString = "";
        hashString = "";
        elapsed = 0;
        elapsedKey = 0;
        stringComplete = false;
        yontemComplete = false;
        yazdim = false;
        yazdimIki = false;
        yontemString = "";
      }
    } else if (yontemString == "b\n") {
      delay(5000);
      if (yazdimIki == false) {
        Serial.println("Şirelenecek metni girin");
        yazdimIki = true;
      }
      while (Serial.available()) {
        char inChar = (char)Serial.read();
        if (inChar == '\n') {
          stringComplete = true;
        } else {
          inputString += inChar;
        }
      }
      hashString = inputString;
      // seri porttan gelen metin tamamlandıysa işlemleri yap
      if (stringComplete) {
        for (int i = 0; i < (hashString.length()); i++ ) {
          testVectorSHA256.data[i] = hashString.charAt(i);
          if (hashString.length() - 1 == i) {
            testVectorSHA256.data[i + 1] = '\0';
          }
        }
        Serial.println();
        testHash(&sha256, &testVectorSHA256);
        while ((inputString.length()) % 16 != 0) {
          inputString.concat("0");
        }
        // seri porttan gelen metni ekrana yazdır
        Serial.println("Gelen metin: " + inputString);
        for (int j = 0; j < ((inputString.length() - 1) / 16); j++) {
          for (int i = 0; i < 16; i++) {
            testVectorAES192.plaintext[i] = inputString.charAt(i + (j * 16)); // her karakter byte dizisine atanıyor
          }
          testCipher(&aes192, &testVectorAES192);
          perfCipher(&aes192, &testVectorAES192);
          cycle = j + 1;
        }
        yontem = 192;
        if (Firebase.setInt(firebaseData, "/yontem", yontem)) {
          delay(1000);
        } else {
          Serial.println(firebaseData.errorReason());
        }

        if (Firebase.setString(firebaseData, "/mesaj", SifreliMetin)) {
          delay(1000);
        } else {
          Serial.println(firebaseData.errorReason());
        }
        Serial.println();
        Serial.print("Performans verileri:");
        Serial.print(elapsed / (5000.0 * 16.0 * cycle));
        Serial.print("us per byte, ");
        Serial.print((16.0 * 5000.0 * 1000000.0 * cycle) / elapsed);
        Serial.println(" bytes per second");
        Serial.println();
        Serial.print("Set Key:");
        Serial.print(elapsedKey / (cycle * 10000.0));
        Serial.print("us per operation, ");
        Serial.print((10000.0 * 1000000.0 * cycle) / elapsedKey);
        Serial.println(" per second");
        Serial.println();
        Serial.print(elapsedHash / (sizeof(bufferHash) * 500.0));
        Serial.print("us per byte, ");
        Serial.print((sizeof(bufferHash) * 500.0 * 1000000.0) / elapsedHash);
        Serial.println(" bytes per second");
        Serial.println();
        SifreliMetin = "";
        inputString = "";
        hashString = "";
        elapsed = 0;
        elapsedKey = 0;
        stringComplete = false;
        yontemComplete = false;
        yazdim = false;
        yazdimIki = false;
        yontemString = "";
      }
    } else if (yontemString == "c\n") {
      delay(5000);
      if (yazdimIki == false) {
        Serial.println("Şirelenecek metni girin");
        yazdimIki = true;
      }
      while (Serial.available()) {
        char inChar = (char)Serial.read();
        if (inChar == '\n') {
          stringComplete = true;
        } else {
          inputString += inChar;
        }
      }
      hashString = inputString;
      // seri porttan gelen metin tamamlandıysa işlemleri yap
      if (stringComplete) {
        for (int i = 0; i < (hashString.length()); i++ ) {
          testVectorSHA256.data[i] = hashString.charAt(i);
          if (hashString.length() - 1 == i) {
            testVectorSHA256.data[i + 1] = '\0';
          }
        }
        Serial.println();
        testHash(&sha256, &testVectorSHA256);
        while ((inputString.length()) % 16 != 0) {
          inputString.concat("0");
        }
        // seri porttan gelen metni ekrana yazdır
        Serial.println("Gelen metin: " + inputString);
        for (int j = 0; j < ((inputString.length()) / 16); j++) {
          for (int i = 0; i < 16; i++) {
            testVectorAES256.plaintext[i] = inputString.charAt(i + (j * 16)); // her karakter byte dizisine atanıyor
          }
          testCipher(&aes256, &testVectorAES256);
          perfCipher(&aes256, &testVectorAES256);
          cycle = j + 1;
        }
        yontem = 256;
        if (Firebase.setInt(firebaseData, "/yontem", yontem)) {
          delay(1000);
        } else {
          Serial.println(firebaseData.errorReason());
        }

        if (Firebase.setString(firebaseData, "/mesaj", SifreliMetin)) {
          delay(1000);
        } else {
          Serial.println(firebaseData.errorReason());
        }
        if (Firebase.setString(firebaseData, "/hash", hashString)) {
          delay(1000);
        } else {
          Serial.println(firebaseData.errorReason());
        }
        Serial.println();
        Serial.print("Performans verileri:");
        Serial.print(elapsed / (5000.0 * 16.0 * cycle));
        Serial.print("us per byte, ");
        Serial.print((16.0 * 5000.0 * 1000000.0 * cycle) / elapsed);
        Serial.println(" bytes per second");
        Serial.println();
        Serial.print("Set Key:");
        Serial.print(elapsedKey / (cycle * 10000.0));
        Serial.print("us per operation, ");
        Serial.print((10000.0 * 1000000.0 * cycle) / elapsedKey);
        Serial.println(" per second");
        Serial.println();
        Serial.print(elapsedHash / (sizeof(bufferHash) * 500.0));
        Serial.print("us per byte, ");
        Serial.print((sizeof(bufferHash) * 500.0 * 1000000.0) / elapsedHash);
        Serial.println(" bytes per second");
        Serial.println();
        SifreliMetin = "";
        inputString = "";
        hashString = "";
        elapsed = 0;
        elapsedKey = 0;
        stringComplete = false;
        yontemComplete = false;
        yazdim = false;
        yazdimIki = false;
        yontemString = "";
      }
    } else {
      Serial.println("hicbiri");
      Serial.println(yontemString);
      SifreliMetin = "";
      inputString = "";
      hashString = "";
      elapsed = 0;
      stringComplete = false;
      yontemComplete = false;
      yazdim = false;
      yazdimIki = false;
      yontemString = "";
      delay(10000);
    }
  }

}
