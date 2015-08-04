# In 32bit vs 64bit builds, some variables can have different type (INT vs BIGINT),
# and/or different max/default values (e.g. 2^32-1 vs 2^64-1 etc.).
# To avoid the trouble with maintaining rdiff files, we'll do the masking here.


if ($MTR_word_size == 64)
{ 
  if ($MTR_is_windows == 0)
  {
    --replace_result 18446744073709551615 '<MAX UNSIGNED>' 9223372036854775807 '<MAX SIGNED>' 18446744073709547520 '<MAX UNSIGNED ADJUSTED>' 9223372036853727232 '<MAX SIGNED ADJUSTED>' BIGINT <[BIG]INT>
  }
}
if ($MTR_word_size == 32)
{ 
    --replace_result 4294967295 '<MAX UNSIGNED>' 2147483647 '<MAX SIGNED>' 4294963200 '<MAX UNSIGNED ADJUSTED>' 2146435072 '<MAX SIGNED ADJUSTED>' INT <[BIG]INT> BIGINT <[BIG]INT> 
}
if ($MTR_is_windows == 1)
{
    --replace_result 4294967295 '<MAX UNSIGNED>' 2147483647 '<MAX SIGNED>' 4294963200 '<MAX UNSIGNED ADJUSTED>' 2146435072 '<MAX SIGNED ADJUSTED>' INT <[BIG]INT> BIGINT <[BIG]INT> 
}

