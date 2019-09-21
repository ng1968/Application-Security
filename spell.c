#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "dictionary.h"

/**
 * Trims punctuation or numbers at the beggining or end of word.
 */
/**
 * Inputs:
 *  word:       A pointer to a word that might have punctuation.
 *  temp_word:  A pointer to variable that will store trimmed word.
 *
 * Modifies:
 *  temp_word: This will stored the trimmed word.
 *
 * Example:
 *  trim_punctuation( word, temp_word);
 **/
void trim_punctuation( char *word, char *temp_word){
  int beginning_word = 0;
  int end_word = strlen(word)-1;

  while( !isalpha(word[beginning_word]) ){
    beginning_word++;
  }

  while( !isalpha(word[end_word]) ){
    end_word--;
  }
  
  int j = 0;
  for( int i = beginning_word; i <= end_word; i++ ){
    temp_word[j] = word[i];
    j++;
  }

  temp_word[strlen(temp_word)]='\0';
}

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
  char* line = malloc(1024);
  while(fgets(line,1024, fp)){
    line[strlen(line)-1]='\0';

    // Read the line.
    // Split the line on spaces.
    char delim[LENGTH] = " ";

    char* words = strtok(line, delim);
    // For each word in line:
    while( words != NULL && num_misspelled < MAX_MISSPELLED){
      char* temp_word = malloc(LENGTH); 

      // Trim punctuation or numbers from word.
      trim_punctuation(words, temp_word);
      // If word is misspelled:
      if( check_word(temp_word, hashtable) == false )
      {
        char* misspelled_word = malloc(LENGTH);
        strncpy(misspelled_word, temp_word, LENGTH);
        misspelled_word[LENGTH - 1] = '\0';
        // Append word to misspelled.
        misspelled[num_misspelled] = misspelled_word;
        // Increment num_misspelled.
        num_misspelled++;
      }
      words = strtok(NULL, delim);
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
  char* temp_word = malloc(LENGTH); 

  // Making all characters in word lower case.
  for( int i = 0; i < strlen(word); i++ ){
    temp_word[i] = tolower(word[i]);
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
    new_node->word[LENGTH-1] = '\0';
    // Set int bucket to hash_function(word).
    int bucket = hash_function(new_node->word);

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
