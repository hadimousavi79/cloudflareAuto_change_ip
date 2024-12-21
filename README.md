# بررسی اجمالی

این برنامه میاد روی سرور خارجتون نه لزوما سرور اصلی نصب میشه بعد میاد  آیپی سرور های ایرانتون رو با دامه هایی که با این آیپی ها ست شده  برسی میکنه بعد هر 120 ثانیه وضعیت اتصال tcp سرورها رو چک میکنه ،   هر کدوم از سرورها به مشکل بخوره و  پینگی دریافت نشه ، به صورت رندوم آیپی اون ساب دامنه رو تغییر میده و   هر 20 ثانیه اون سروری که  مشکل اتصال داره  چک میکنه  زمانی که اتصال سرور دوباره برقرار شد  ساب دامین رو به حالت اول برمیگردونه . .

# توجه
- همه سرورهای ایرانتون باید  تانل شده  باشن 

- برای مثال اگه شما یک سرور خارج دارید حتما باید روی تمام سرور های ایران تانل شده باشه و با هر ایپی ایران بشه متصل شد

-  سروری که این برنامه روش نصب هستش نباید ریست بشه با هر ریستارت باید دوباره برنامه رو ران کنید


# راهنمای نصب
برای نصب کافیه دستور زیر رو اجرا کنید

```bash
curl -Ls https://raw.githubusercontent.com/Free-Guy-IR/cloudflareAuto_change_ip/main/install.sh | bash

```


وقتی نصب تمام شد:

اولین سوال :
باید تعداد دامنه هاتون رو مشخص کنید  مثلا اگر دو دامنه دارید عدد 2 را وارد کنید 

```
How many domains (zones) do you have? 

```
Zon ID  دامنه هارو باید وارد کنید
```
Enter the Zone ID for domain 1: 
```
```
Enter the Zone ID for domain 2:
```
تعداد سرور های بکاپتون رو باید وارد کنید
```
How many servers do you have? 
```
آیپی سرور هارو باید به ترتیب وارد کنید 
```
Enter the IP of server 1: 
```
بعد وارد کردن آیپی باید پورت TCP   اون سرور رو وارد کنید ( حتما پورت تانل شده باشه که اگه تانل حتی قطع شد  برنامه  بتونه بفهمه )
```
Enter the TCP port for server 1: 
```

اولیت سرور رو مشخص کنید (1 بیشترین اولیت   و هر عدد بعد 1 به ترتیب اولیت بندی میشه )

```
Enter the priority for server 1 (1 = highest priority): 
```
Global API token اکانت کلودفلرتون رو باید وارد کنید ( از بخش پروفایل)
```
Enter your Cloudflare Global API token: 
```
توکن ربات تلگرام باید وارد کنید
```
Enter your Telegram bot token:
```
چت آیدی  اکانت تلگرام که قراره اطلاع رسانی به ایشون ارسال بشه
``` 
Enter your Telegram chat ID: 
```
مقدار زمان انتظار برای برسی دوباره سرور ها ( ثانیه )
```
Enter the interval for checking servers (in seconds, default 120): 

```





وقتی  تغییرات انجام دادید  یک بار برنامه متوقف کنید و با  روش زیر اجرا کنید تا متوقف نشه
```
screen

python3 cloudflareAuto_change_ip.py

```


 [لینک کانال تلگرام اطلاع رسانی بروزرسانی های من](https://t.me/Freeguy_IR)

