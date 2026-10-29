-- آکادمی زبان استاد مهدوی: جداول، نقش‌ها و دسترسی‌های پایه برای Supabase
-- این فایل را یک‌بار در SQL Editor پروژه Supabase اجرا کن.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text not null default 'student' check (role in ('student','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.courses (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text not null default '',
  level text not null default 'مبتدی',
  duration text not null default 'قابل تنظیم',
  price integer not null default 0 check (price >= 0),
  is_free boolean not null default true,
  published boolean not null default false,
  cover_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.lessons (
  id uuid primary key default gen_random_uuid(),
  course_id uuid not null references public.courses(id) on delete cascade,
  title text not null,
  content text not null default '',
  order_no integer not null default 1 check (order_no > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.enrollments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  course_id uuid not null references public.courses(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique(user_id, course_id)
);
create index if not exists lessons_course_order_idx on public.lessons(course_id, order_no);
create index if not exists enrollments_user_idx on public.enrollments(user_id);
create index if not exists enrollments_course_idx on public.enrollments(course_id);

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'); $$;
grant execute on function public.is_admin() to authenticated;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$ begin
  insert into public.profiles(id,email,role) values(new.id,new.email,'student')
  on conflict (id) do update set email = excluded.email;
  return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.courses enable row level security;
alter table public.lessons enable row level security;
alter table public.enrollments enable row level security;

-- حذف دسترسی‌های پیش‌فرض باز؛ سپس فقط دسترسی لازم اعطا می‌شود.
revoke all on public.profiles from anon, authenticated;
revoke all on public.courses from anon, authenticated;
revoke all on public.lessons from anon, authenticated;
revoke all on public.enrollments from anon, authenticated;
grant select on public.courses to anon, authenticated;
grant insert, update, delete on public.courses to authenticated;
grant select on public.lessons to authenticated;
grant insert, update, delete on public.lessons to authenticated;
grant select on public.profiles to authenticated;
grant select, insert, delete on public.enrollments to authenticated;

-- Profiles: زبان‌آموز فقط پروفایل خودش را می‌خواند؛ مدیر می‌تواند همه را ببیند.
drop policy if exists "profiles_read_self_or_admin" on public.profiles;
create policy "profiles_read_self_or_admin" on public.profiles for select to authenticated
using (id = (select auth.uid()) or (select public.is_admin()));

-- دوره‌های منتشرشده برای همه قابل مشاهده‌اند؛ نوشتن فقط برای مدیر.
drop policy if exists "courses_read_published" on public.courses;
create policy "courses_read_published" on public.courses for select to anon, authenticated
using (published = true or (select public.is_admin()));
drop policy if exists "courses_admin_insert" on public.courses;
create policy "courses_admin_insert" on public.courses for insert to authenticated with check ((select public.is_admin()));
drop policy if exists "courses_admin_update" on public.courses;
create policy "courses_admin_update" on public.courses for update to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));
drop policy if exists "courses_admin_delete" on public.courses;
create policy "courses_admin_delete" on public.courses for delete to authenticated using ((select public.is_admin()));

-- درس‌ها فقط برای مدیر، ثبت‌نام‌کنندگان آن دوره، یا دوره رایگان قابل خواندن‌اند.
drop policy if exists "lessons_read_access" on public.lessons;
create policy "lessons_read_access" on public.lessons for select to authenticated
using (
  (select public.is_admin()) or exists(select 1 from public.courses c where c.id = course_id and c.is_free = true and c.published = true)
  or exists(select 1 from public.enrollments e where e.course_id = lessons.course_id and e.user_id = (select auth.uid()))
);
drop policy if exists "lessons_admin_insert" on public.lessons;
create policy "lessons_admin_insert" on public.lessons for insert to authenticated with check ((select public.is_admin()));
drop policy if exists "lessons_admin_update" on public.lessons;
create policy "lessons_admin_update" on public.lessons for update to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));
drop policy if exists "lessons_admin_delete" on public.lessons;
create policy "lessons_admin_delete" on public.lessons for delete to authenticated using ((select public.is_admin()));

-- زبان‌آموز فقط می‌تواند خودش را در دوره رایگان ثبت‌نام کند؛ مدیر می‌تواند دسترسی بدهد یا لغو کند.
drop policy if exists "enrollments_read_self_or_admin" on public.enrollments;
create policy "enrollments_read_self_or_admin" on public.enrollments for select to authenticated
using (user_id = (select auth.uid()) or (select public.is_admin()));
drop policy if exists "enrollments_insert_free_or_admin" on public.enrollments;
create policy "enrollments_insert_free_or_admin" on public.enrollments for insert to authenticated
with check (
  (select public.is_admin()) or (
    user_id = (select auth.uid()) and exists(select 1 from public.courses c where c.id = course_id and c.is_free = true and c.published = true)
  )
);
drop policy if exists "enrollments_delete_self_or_admin" on public.enrollments;
create policy "enrollments_delete_self_or_admin" on public.enrollments for delete to authenticated
using (user_id = (select auth.uid()) or (select public.is_admin()));

-- دوره‌های نمونه (قابل ویرایش از پنل مدیریت)
insert into public.courses(title,description,level,duration,price,is_free,published,cover_url)
select v.title,v.description,v.level,v.duration,v.price,v.is_free,v.published,null
from (values
('انگلیسی از پایه','در این دوره از سلام‌و‌احوال‌پرسی و جمله‌های ساده شروع می‌کنیم. هر درس توضیح کوتاه، مثال انگلیسی با ترجمه فارسی و تمرین دارد.','مبتدی','۸ هفته',0,true,true),
('مکالمه روزمره انگلیسی','عبارت‌های کاربردی برای خرید، پرسیدن مسیر، معرفی خود و گفت‌وگوهای کوتاه؛ همراه با نمونه مکالمه و نکته‌های تلفظ.','متوسط','۶ هفته',0,true,true),
('گرامر کاربردی و جمله‌سازی','مروری بر زمان حال ساده، حال استمراری و ساخت سؤال و منفی؛ با مثال‌های کوتاه و تمرین‌های قابل مرور.','مبتدی تا متوسط','۵ هفته',0,true,true)
) as v(title,description,level,duration,price,is_free,published)
where not exists (select 1 from public.courses c where c.title = v.title);

-- درس‌های نمونه؛ برای هر دوره فقط در صورت خالی‌بودن درس‌ها وارد می‌شوند.
do $$
declare c1 uuid; c2 uuid; c3 uuid;
begin
 select id into c1 from public.courses where title='انگلیسی از پایه' limit 1;
 select id into c2 from public.courses where title='مکالمه روزمره انگلیسی' limit 1;
 select id into c3 from public.courses where title='گرامر کاربردی و جمله‌سازی' limit 1;
 if c1 is not null and not exists(select 1 from public.lessons where course_id=c1) then
  insert into public.lessons(course_id,title,content,order_no) values
  (c1,'درس ۱: سلام و معرفی خود','در انگلیسی برای سلام‌کردن می‌توانیم بگوییم Hello یا Hi.

Hello! = سلام!
My name is Sara. = اسم من سارا است.
What is your name? = اسم تو چیست؟

نکته: برای معرفی خود از ساختار My name is … استفاده کن. در مکالمه دوستانه، I’m … هم رایج است.',1),
  (c1,'درس ۲: ضمیرهای فاعلی','I = من، You = تو/شما، He = او (مذکر)، She = او (مونث)، It = آن، We = ما، They = آن‌ها.

I am a student. = من دانش‌آموزم.
She is happy. = او خوشحال است.
They are friends. = آن‌ها دوست هستند.

تمرین: با I، He و They سه جمله بساز.',2),
  (c1,'درس ۳: فعل to be در زمان حال','شکل‌های اصلی فعل to be در زمان حال am، is و are هستند.
I am؛ He/She/It is؛ You/We/They are.

I am ready. = من آماده‌ام.
He is at home. = او در خانه است.
We are students. = ما دانش‌آموز هستیم.

برای منفی‌کردن، not اضافه کن: I am not tired. = من خسته نیستم.',3),
  (c1,'درس ۴: پرسش‌های ساده','برای سؤال بله/خیر با فعل to be، فعل را قبل از فاعل می‌آوریم.
You are ready. → Are you ready?
She is a teacher. → Is she a teacher?

پاسخ کوتاه: Yes, I am. / No, I’m not.
تمرین: جمله They are happy را به سؤال تبدیل کن.',4);
 end if;
 if c2 is not null and not exists(select 1 from public.lessons where course_id=c2) then
  insert into public.lessons(course_id,title,content,order_no) values
  (c2,'درس ۱: شروع یک گفت‌وگو','How are you? = حالت چطور است؟
I’m fine, thanks. = خوبم، ممنون.
Nice to meet you. = از آشنایی با تو خوشحالم.

نمونه:
A: Hi! How are you?
B: I’m good, thanks. And you?
A: I’m great!

نکته: پاسخ کوتاه و طبیعی در مکالمه روزمره بسیار کاربردی است.',1),
  (c2,'درس ۲: سفارش در کافه','عبارت Can I have …, please? برای درخواست مؤدبانه کاربرد دارد.
Can I have a tea, please? = می‌شود یک چای لطفاً؟
How much is it? = قیمتش چقدر است؟
That’s all, thank you. = همین، ممنون.

تمرین: به‌جای tea نام یک نوشیدنی دیگر بگذار.',2),
  (c2,'درس ۳: پرسیدن مسیر','Excuse me, where is the station? = ببخشید، ایستگاه کجاست؟
Go straight. = مستقیم برو.
Turn left/right. = به چپ/راست بپیچ.
It’s next to the bank. = کنار بانک است.

برای شروع درخواست کمک، Excuse me عبارت مؤدبانه‌ای است.',3);
 end if;
 if c3 is not null and not exists(select 1 from public.lessons where course_id=c3) then
  insert into public.lessons(course_id,title,content,order_no) values
  (c3,'درس ۱: حال ساده','از حال ساده برای عادت‌ها و واقعیت‌ها استفاده می‌کنیم.
I play football every week. = من هر هفته فوتبال بازی می‌کنم.
She works at a school. = او در مدرسه کار می‌کند.

برای he/she/it معمولاً به فعل s اضافه می‌شود: work → works.
منفی: I don’t play. / She doesn’t play.
تمرین: یک عادت روزانه خودت را به انگلیسی بنویس.',1),
  (c3,'درس ۲: حال استمراری','برای کاری که همین حالا در جریان است، از am/is/are + فعل ing استفاده می‌کنیم.
I am reading. = من دارم مطالعه می‌کنم.
They are playing. = آن‌ها دارند بازی می‌کنند.

I read every day = عادت؛ I am reading now = همین لحظه.',2),
  (c3,'درس ۳: سؤال‌سازی با do و does','در حال ساده برای سؤال از Do یا Does استفاده می‌کنیم.
Do you like music? = موسیقی دوست داری؟
Does he play tennis? = آیا او تنیس بازی می‌کند؟

پس از does، فعل اصلی s نمی‌گیرد: Does she work? (نه Does she works?)',3);
 end if;
end $$;
