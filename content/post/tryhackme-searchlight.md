+++
title = "Tryhackme Searchlight IMINT"
description = "A tryhackme machine on osint."
date = 2020-12-22T17:35:09-05:00
draft = false
+++
![](https://i.imgur.com/rVULTsB.png)

OSINT challenges in the imagery intelligence category

**Note Important, Format flag is : sl{strings}**

#### # Description
In this room, we will be exploring the discipline of IMINT/GEOINT, which is short for Image intelligence and geospatial intelligence. This room is suited to those of you who are just beginning your OSINT journey or those brand new to the field of IMINT/GEOINT.

#### # Task 1 : Welcome to the Searchlight IMINT room!.\
Question : Did you understand the flag format?

```
sl{ready}
```

#### # Task 2 :  Your first challenge!
Question : What is the name of the street where this image was taken?\
Looking closely, on the welcome sign we see the name of the street.

![](https://imgur.com/lT4LJCO.jpg)

```
sl{carnaby street}
```

#### # Task 3 : Just Google it!\
![](https://imgur.com/uLJFxcD.jpg)

There are four questions in this task:

    1. Which city is the tube station located in?
    2. Which tube station do these stairs lead to?
    3. Which year did this station open?
    4. How many platforms are there in this station?\
1 : 

Looking for the image in `Google Images` or in` Yandex` we could find the underground train station looking for we found in [Wikipedia London Undergraund](https://en.wikipedia.org/wiki/London_Underground)

```
sl{london}
```

2 : 

By zooming in on the sign covered by the staircase, we can see the last three letters of the first word referring to a London circus.We can google with the following dork `London Underground Circus`
![](https://i.imgur.com/z3xC1dd.png)
```
sl{Piccadilly circus}
```

3 :

Based on the search for the previous task in Wikipedia we can easily find the following answers. [Wikipedia Poccadilly Circus](https://en.wikipedia.org/wiki/Piccadilly_Circus_tube_station))
![](https://i.imgur.com/dsiV2zk.png)
```
sl{1906}
```

4 : 

```
sl{4}
```
#### # Task 4 : Keep at it!
This challenge is a bit harder then the previous one mainly because there is less information to see, but I can still see people sitti$
There is also a big banner with something that looks like a website on the bottom right corner - YVR.CA.
Going to that website we are welcomed into Vancouver international airport which is the building we're looking for.

![](https://i.imgur.com/Z7wyiKl.jpg)

There are four questions in this task:

	1. Which building is this photo taken in?
	2. Which country is this building located in?
	3. Which city is this building located in?
1 : 

`Continue..`
