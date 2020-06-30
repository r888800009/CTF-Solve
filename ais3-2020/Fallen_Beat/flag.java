public class flag {
  static byte[] flag = new byte[] {89, 74, 75, 43, 126, 69, 120, 109, 68, 109, 109, 97, 73, 110, 45,
      113, 102, 64, 121, 47, 111, 119, 111, 71, 114, 125, 68, 105, Byte.MAX_VALUE, 124, 94, 103, 46,
      107, 97, 104};
  public static void main(String[] args) {
    // for (i = 0; i < cache.size(); i++)
    //   flag[i % flag.length] = (byte) (flag[i % flag.length] ^ ((Integer)
    //   cache.get(i)).intValue());
    String fff = new String(flag);

    System.out.println(flag);
    System.out.println(String.format("Flag: %s", new Object[] {fff}));
  }
}
