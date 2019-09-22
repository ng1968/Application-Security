#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dictionary.h"
//#include "spell.c"
//#include "dictionary.c"

int main(int argc, char **argv)
{ 
  char* file_to_test = argv[1];
  char* dictionary_file = argv[2];

  hashmap_t hashtable[HASH_SIZE];
  char* misspelled[MAX_MISSPELLED];

  printf("Loading Dictionary from file: %s.\n", dictionary_file);
  load_dictionary(dictionary_file, hashtable);
  printf("Dictionary Loaded\n");
 
  const char* question_mark_word = "Test";
  if(check_word(question_mark_word, hashtable)){
    printf("%s is correctly spelled.\n", question_mark_word);
  }
  
  FILE *fp = fopen(file_to_test, "r");
  printf("Opended file to be checked: %s.\n", file_to_test);

  printf("Running checks\n");
  int misspelled_num = check_words(fp, hashtable, misspelled);

  printf("\nThere were %d misspelled\n", misspelled_num);
  for(int i = 0; i < misspelled_num; i++){
  	printf("%s\n", misspelled[i]);
  }
  
  return 0;
}
