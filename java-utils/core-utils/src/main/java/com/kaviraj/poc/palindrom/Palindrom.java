package com.kaviraj.poc.palindrom;

import java.util.ArrayList;
import java.util.List;

public class Palindrom {

	public static void main(String[] args) {
		String myString = "Malaya";
		String myString1 = "Malayala";
		String myString2 = "lam";
		List<String> myList = new ArrayList<String>();
		myList.add(myString2);
		myList.add(myString1);
		myList.add(myString);

		// myList.removeIf(filter)
		for (String string : myList) {
			for (int i = 0; i < myList.size(); i++) {
				if (isPalindrom(string + myList.get(i))) {
					System.out.println(string + " " + myList.get(i));
				}

			}

		}

	}

	private static boolean isPalindrom(String myString) {
		int length = myString.length();
		for (int i = 0; i < length / 2; i++) {
			char[] newString = myString.toUpperCase().toCharArray();

			if (!(newString[i] == newString[length - 1 - i])) {
				return false;
			}
		}
		return true;
	}
}
