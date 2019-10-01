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

  load_dictionary(dictionary_file, hashtable);
  
  FILE *fp = fopen(file_to_test, "r");

  int misspelled_num = check_words(fp, hashtable, misspelled);

  int i = 0;
  while( i < misspelled_num ){
    printf("%s", misspelled[i]);
    if ((i + 1) < misspelled_num)
      printf(", ");
    else
      printf("\n");
    i++;
  }
  
  return 0;
}
