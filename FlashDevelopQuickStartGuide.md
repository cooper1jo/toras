# Introduction #

This page details how to set up the FlashDevelop IDE to compile the "full featured" version of TorAS, including the ability to launch and control the included Tor binary.

If you're an experienced ActionScript developer you can skip directly to the third step to ensure that your application is being produced with the correct desktop profile.

Additionally, if you're an experienced developer who prefers tools such as Adobe Flash Builder, you should consider this entire document entirely optional -- you should be able to use the source code directly; simply copy it from the "src" folder.

# Step 1: Install Software #

You will need to download install the following software before you can compile TorAS:

  * **TortoiseSVN**: http://tortoisesvn.net/
  * **FlashDevelop**: http://www.flashdevelop.org/

# Step 2: Checkout TorAS Source Code #

Create a folder in which the TorAS source code will be stored. Right-click on this folder and select "SVN Checkout..." from the context menu.

Paste the following URL into the "URL of Repository" field, then click OK:
http://toras.googlecode.com/svn/trunk/

Once you've checked out the source code, you can always update to the most recent version, or restore any accidentally deleted or changed files, by right-clicking on the TorAS folder and selecting "SVN Update".

# Step 3: Set up FlashDevelop #

This final step is required to be able to compile and run the "full" version of TorAS, including the ability to dynamically invoke and control the Tor process (tor.exe).

  * Run FlashDevelop.
  * From the main menu, select Project -> New Project...
  * In the ActionScript 3 selection area, select "AIR AS3 Projector"
  * Give the project any name you like (TorAS is recommended).
  * For the Location, browse to the main folder into which TorAS was checked out in Step 2 (do not select the "src" or "bin" folders). Click OK.
  * FlashDevelop will warn you that the directory to which you will be copying template files is not empty. This is not a problem so click OK.
  * From the main menu, select Project -> AIR App Properties...
  * Select the "Installation" tab, and ensure that the "Extended Desktop" profile is selected (checked). Click OK.
  * In the Project pane (View -> Project Manager), open the "src" folder and ensure that the "Main" class is selected as the document class. To do this, right-click on the class and ensure "Document Class" is checked.

# Step 4: Compile and Play #

You should now be able to compile TorAS (CTRL-ENTER, F5, or Project -> Test Project). There is no user interface, so all messages and information will be visible in the Output panel (View -> Output Panel).

The "Main" class demonstrates how to properly initialize TorAS, as well as how to invoke some of the library's major functions.