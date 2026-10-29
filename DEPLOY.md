# راهنمای خیلی کوتاه انتشار

1. ابتدا پروژه Supabase را بساز و `supabase-setup.sql` را اجرا کن.
2. مقادیر URL و کلید عمومی را در `config.js` قرار بده.
3. محتویات همین پوشه را در ریشه مخزن GitHub آپلود و Commit کن.
4. در Cloudflare Pages مخزن GitHub را وصل کن: Framework preset = None، Build command = خالی، Build output directory = `.`.
5. پس از اولین انتشار، دامنه `*.pages.dev` را در Supabase Authentication → URL Configuration به Site URL و Redirect URLs اضافه کن.
6. حساب خودت را بساز و با دستور README نقش `admin` را فعال کن.
