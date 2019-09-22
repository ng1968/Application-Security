#include <check.h>
#include "dictionary.h"
#include <stdlib.h>

#define DICTIONARY "wordlist.txt"
#define TESTDICT "test_worlist.txt"
#define ABNORMAL_CASES "abnormal_cases.txt"

START_TEST(test_dictionary_normal)
{
    hashmap_t hashtable[HASH_SIZE];
    ck_assert(load_dictionary(TESTDICT, hashtable));
    // Here we can test if certain words ended up in certain buckets
    // to ensure that our load_dictionary works as intended. I leave
    // this as an exercise.
    const char* expected_first = "first";
    const char* expected_fourth = "fourth";
    int bucket_first = hash_function(expected_first);
    int bucket_fourth = hash_function(expected_fourth);
    ck_assert(strncmp(hashtable[bucket_first]->word, expected_first, LENGTH) == 0);
    ck_assert( hashtable[bucket_fourth] == NULL );
}
END_TEST

START_TEST(test_dictionary_abnormal)
{
    hashmap_t hashtable[HASH_SIZE];
    ck_assert(!load_dictionary("idontexits.txt", hashtable));
}
END_TEST

START_TEST(test_dictionary_overflow)
{
    hashmap_t hashtable[HASH_SIZE];
    ck_assert(load_dictionary("long_word.txt", hashtable));
    ck_assert(strncmp(hashtable[587]->word, "Supercalifragilisticexpialidociouissomethin", LENGTH) == 0);
    ck_assert(strncmp(hashtable[1533]->word, "marypoppingssa", LENGTH) == 0);
}
END_TEST

START_TEST(test_check_word_normal)
{
    hashmap_t hashtable[HASH_SIZE];
    ck_assert(load_dictionary(DICTIONARY, hashtable));
    const char* correct_word = "Justice";
    const char* punctuation_word_2 = "pl.ace";
    const char* punctuation_word_3 = "?pl.ace?";
    ck_assert(check_word(correct_word, hashtable));
    ck_assert(!check_word(punctuation_word_2, hashtable));
    ck_assert(!check_word(punctuation_word_3, hashtable));
}
END_TEST

START_TEST(test_check_word_overflow)
{
    hashmap_t hashtable[HASH_SIZE];
    ck_assert(load_dictionary(DICTIONARY, hashtable));
    const char* long_word = "Supercalifragilisticexpialidociouissomethingmarypoppingssay";
    ck_assert(!check_word(long_word, hashtable));
}
END_TEST

START_TEST(test_check_words_normal)
{
    hashmap_t hashtable[HASH_SIZE];
    load_dictionary(DICTIONARY, hashtable);
    char* expected[3];
    expected[0] = "sogn";
    expected[1] = "skyn";
    expected[2] = "betta";
    char *misspelled[MAX_MISSPELLED];
    FILE *fp = fopen("test1.txt", "r");
    int num_misspelled = check_words(fp, hashtable, misspelled);
    ck_assert(num_misspelled == 3);
    bool test = strlen(misspelled[0]) == strlen(expected[0]);
    int len1 = strlen(misspelled[0]);
    int len2 = strlen(expected[0]);
    ck_assert_msg(test, "%d!=%d", len1, len2);
    ck_assert_msg(strcmp(misspelled[0], expected[0]) == 0);
    ck_assert_msg(strcmp(misspelled[1], expected[1]) == 0);
    ck_assert_msg(strcmp(misspelled[2], expected[2]) == 0);
}
END_TEST

START_TEST(test_check_words_abnormal)
{
    hashmap_t hashtable[HASH_SIZE];
    ck_assert(load_dictionary(DICTIONARY, hashtable));
    
    char *misspelled[MAX_MISSPELLED];
    FILE *fp = fopen(ABNORMAL_CASES, "r");
    int num_misspelled = check_words(fp, hashtable, misspelled);
    ck_assert(num_misspelled == 2);
    ck_assert(strncmp(misspelled[0], "seco234nd", LENGTH) == 0);
    ck_assert(strncmp(misspelled[1], "fir1st", LENGTH) == 0);
}
END_TEST

START_TEST(test_check_words_overflow)
{
    hashmap_t hashtable[HASH_SIZE];
    ck_assert(load_dictionary(DICTIONARY, hashtable));
    
    char *misspelled[MAX_MISSPELLED];
    FILE *fp = fopen("long_word2.txt", "r");
    int num_misspelled = check_words(fp, hashtable, misspelled);
    ck_assert(num_misspelled == 1);
    ck_assert(strncmp(misspelled[0], "pneumonoultramicroscopicsilicovolcanoconiosis", LENGTH) == 0);
}
END_TEST

START_TEST(test_check_words_max_misspelled)
{
    hashmap_t hashtable[HASH_SIZE];
    ck_assert(load_dictionary(DICTIONARY, hashtable));
    
    char *misspelled[MAX_MISSPELLED];
    FILE *fp = fopen("misspelled.txt", "r");
    int num_misspelled = check_words(fp, hashtable, misspelled);
    ck_assert(num_misspelled == MAX_MISSPELLED);
}
END_TEST

Suite *
check_word_suite(void)
{
    Suite * suite;
    TCase * check_word_case;
    suite = suite_create("check_word");
    check_word_case = tcase_create("Core");
    tcase_add_test(check_word_case, test_dictionary_normal);
    tcase_add_test(check_word_case, test_dictionary_abnormal);
    tcase_add_test(check_word_case, test_dictionary_overflow);
    tcase_add_test(check_word_case, test_check_word_normal);
    tcase_add_test(check_word_case, test_check_word_overflow);
    tcase_add_test(check_word_case, test_check_words_normal);
    tcase_add_test(check_word_case, test_check_words_abnormal);
    tcase_add_test(check_word_case, test_check_words_overflow);
    tcase_add_test(check_word_case, test_check_words_max_misspelled);
    suite_add_tcase(suite, check_word_case);

    return suite;
}

int
main(void)
{
    int failed;
    Suite *suite;
    SRunner *runner;
    
    suite = check_word_suite();
    runner = srunner_create(suite);
    srunner_run_all(runner, CK_NORMAL);
    failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
