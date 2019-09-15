#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dictionary.h"
 
#define DICTIONARY "wordlist.txt"

int main()
{  
  hashmap_t hashtable[HASH_SIZE];
  char* misspelled[MAX_MISSPELLED];

  load_dictionary(DICTIONARY, hashtable);
  printf("load_dictionary complete\n");
  
  const char* correct_word = "inappropriateness's";
  int bucket = hash_function(correct_word);
  printf("\nbucket: %d, word: %s\n", bucket, hashtable[bucket]->word);

  if( check_word(correct_word, hashtable) ){
  	printf("\n%s was correctly spelled.\n", correct_word);
  }

  FILE *fp = fopen("test1.txt", "r");
  printf("Opended file\n");
  int misspelled_num = check_words(fp, hashtable, misspelled);
  printf("checked words\n");
  printf("\nThere were %d misspelled\n", misspelled_num);
  for(int i = 0; i < misspelled_num; i++){
  	printf("%s\n", misspelled[i]);
  }
  
  return 0;
}
