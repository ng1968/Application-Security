#include <stdio.h>
#include "dictionary.h"

/**
 * Array misspelled is populated with words that are misspelled. Returns the length of misspelled.
 */
/**
 * Inputs:
 *  fp:         A file pointer to the document to check for spelling errors.
 *  hashtable:  The hash table used to determine spelling
 *  misspelled: An empty char* array to be populated with misspelled words.
 *              This array will never be greater than 1000 words long.
 *
 * Returns:
 *  int:        The number of words in the misspelled arary.
 *
 * Modifies:
 *  misspelled: This array will be filled with misspelled words.
 *
 * Example:
 *  int num_misspelled = check_words(text_file, hashtable, misspelled);
 **/
int check_words(FILE* fp, hashmap_t hashtable[], char* misspelled[]){
  // Set int num_misspelled to 0.
  int num_misspelled = 0;

  // While line in fp is not EOF (end of file):
  char line[1024];
  while(fgets(line,sizeof line, fp)){
    line[strlen(line)-1]='\0';
    printf("%s\n", line);

    // Read the line.
    // Split the line on spaces and punctuation.
    // https://stackoverflow.com/questions/26597977/split-string-with-multiple-delimiters-using-strtok-in-c
    char delim[LENGTH] = "!@#$%^&*()_+-=[]{};\':\"<>,./?\\| ";
    int i = 0;

    char *words[LENGTH]; // Buffer
    words[i] = strtok(line, delim);
    // For each word in line:
    while( words[i] != NULL )
    {
      printf("%s\n", words[i]);
      // If not check_word(word):
      if( check_word(words[i], hashtable) == false )
      {
        char* misspelled_word = malloc(LENGTH);
        strcpy(misspelled_word, words[i]);
        // Append word to misspelled.
        misspelled[num_misspelled] = misspelled_word;
        // Increment num_misspelled.
        num_misspelled++;
        //for(int i = 0; i < num_misspelled; i++){
          //printf("number: %d word %s\n", i, misspelled[i]);
        //}
      }
      i++;
      words[i] = strtok(NULL, delim);
    }
  }

  fclose(fp);
  // Return num_misspelled.
  return num_misspelled;
}

/**
 * Returns true if word is in dictionary else false.
 */
/**
 * Inputs:
 *  word:       A word to check the spelling of.
 *  hashtable:  The hash table used to determine spelling
 *
 * Returns:
 *  bool:       A boolean value indicating if the word was correctly spelled.
 *
 * Modifies:
 *
 * Example:
 *  bool correct  = check_word(word, hashtable);
 **/
bool check_word(const char* word, hashmap_t hashtable[]){
  // Remove punctuation from beginning and end of word.
  char punctuation[LENGTH];
  strcpy(punctuation, "!\"#$%&\'()*+,-./:;?@[\\]^_`{|}~ ");
  char* temp_word = malloc(LENGTH); 

  int beginning_word = 0;
  int end_word = strlen(word);

  for( int i = 0; i < strlen(punctuation); i++ ){
    if( word[0] == punctuation[i] ){
      beginning_word = 1;
    }

    if( word[end_word-1] == punctuation[i] ){
      if( beginning_word == 1 ){
        end_word = end_word - 2;
      }
      else{
        end_word = end_word - 1;
      }
    }
  }

  for( int i = 0; i < end_word; i++ ){
    temp_word[i] = word[i + beginning_word];
  }

  // By default all lower_case(word) equals cursor:
  for( int i = 0; i < strlen(temp_word); i++ ){
    temp_word[i] = tolower(temp_word[i]);
  }
  // Set int bucket to the output of hash_function(word).
  int bucket = hash_function(temp_word);
  // Set hashmap_t cursor equal to hashmap[bucket].
  hashmap_t cursor = hashtable[bucket];

  // While cursor is not NULL:
  while( cursor != NULL ){
    //If word equals cursor->word:
    if( strcmp(temp_word, cursor->word) == 0 ){
      // return True.
      return true;
    }
    // Set cursor to cursor->next.
    cursor = cursor->next;
  }
  // return False.
  return false;
}

/**
 * Loads dictionary into memory.  Returns true if successful else false.
 */
/**
 * Inputs:
 *  dictionary_file:    Path to the words file.
 *  hashtable:          The hash table to be populated.
 *
 * Returns:
 *  bool:       Whether or not the hashmap successfully populated.
 *
 * Modifies:
 *  hashtable: This hashmap should be filled with words from the file provided.
 *
 * Example:
 *  bool success = load_dictionary("wordlist.txt", hashtable);
 **/
bool load_dictionary(const char* dictionary_file, hashmap_t hashtable[]){
  // Initialize all values in hash table to NULL.
  for( int i = 0; i < HASH_SIZE; i++ ){
    hashtable[i] = NULL;
  }

  // Open dict_file from path stored in dictionary.
  FILE* dict_file = fopen(dictionary_file, "r");

  // If dict_file is NULL:
  if( dict_file == NULL ){
    // return false.
    return false;
	}

  // While word in dict_file is not EOF (end of file):
  char word[LENGTH];
  while( fgets(word,sizeof word, dict_file) ){
  	// Removed new line character
  	word[strlen(word)-1]='\0';

    // Set hashmap_t new_node to a new node.
    // Set new_node->next to NULL.
    // Set new_node->word equal to word.
    node* new_node = malloc(sizeof(node));
    new_node->next = NULL;
    strncpy(new_node->word, word, LENGTH);

    // Set int bucket to hash_function(word).
    int bucket = hash_function(word);

    // if hashtable[bucket] is NULL:
    if( hashtable[bucket] == NULL ){
      // Set hashtable[bucket] to new_node.
      hashtable[bucket] = new_node;
    }
    // else
    else{
      //Set new_node->next to hashtable[bucket].
      new_node->next = hashtable[bucket];
      // Set hashtable[bucket] to new_node.
      hashtable[bucket] = new_node;
    }
  }

  return true;
}